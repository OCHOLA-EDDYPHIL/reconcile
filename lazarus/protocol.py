from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


CASE_SCHEMA_VERSION = "lazarus.case/v1"
SEMANTIC_SCHEMA_VERSION = "lazarus.semantic-proposal/v2"
EVIDENCE_PACKET_SCHEMA_VERSION = "lazarus.evidence-packet/v1"

CASE_SPLITS = frozenset({"calibration", "heldout"})
ARTIFACT_KINDS = frozenset(
    {
        "terraform_plan",
        "service_manifest",
        "ownership",
        "recovery_ledger",
        "change_ticket",
        "change_ticket_text",
        "pr_description",
        "runbook",
        "incident",
        "history",
    }
)
ARTIFACT_AUTHORITIES = frozenset(
    {"structured_fact", "declared_context", "advisory_context"}
)
RELATION_TYPES = frozenset(
    {
        "intent_effect_contradiction",
        "resource_alias_candidate",
        "conditional_dependency_candidate",
        "owner_candidate",
        "incident_relevance_advisory",
        "probe_selection",
    }
)
PROBE_IDS = frozenset(
    {
        "verify_resource_generation",
        "verify_recovery_scope",
        "verify_owner_record",
        "run_application_canary",
    }
)
RELATION_EVIDENCE_CLASSES = {
    "intent_effect_contradiction": "candidate_inference",
    "resource_alias_candidate": "candidate_inference",
    "conditional_dependency_candidate": "candidate_inference",
    "owner_candidate": "candidate_inference",
    "incident_relevance_advisory": "semantic_proposal",
    "probe_selection": "semantic_proposal",
}

RECOVERY_STATUSES = frozenset({"pass", "fail", "unknown"})
SEMANTIC_STATUSES = frozenset({"not_requested", "unavailable", "available"})
HUMAN_DECISION_STATES = frozenset(
    {"ready_for_human_decision", "blocked", "needs_confirmation"}
)
CANARY_CHECK_TYPES = frozenset(
    {"integrity", "schema", "required_query", "business_invariant"}
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_JSON_TYPES = (type(None), bool, int, float, str, list, dict)


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


class ProtocolValidationError(ValueError):
    def __init__(self, contract: str, issues: Sequence[ValidationIssue]):
        self.contract = contract
        self.issues = tuple(issues)
        detail = "; ".join(
            f"{issue.path}: {issue.message}" for issue in self.issues
        )
        super().__init__(f"invalid {contract}: {detail}")


def canonical_json(value: Any) -> str:
    _assert_json_value(value)
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"value cannot be encoded as canonical JSON: {exc}") from exc


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return canonical_json(value).encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("canonical JSON strings must contain valid Unicode") from exc


def canonical_json_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def artifact_digest(value: str | bytes) -> str:
    if isinstance(value, str):
        try:
            payload = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError("artifact text must contain valid Unicode") from exc
    elif isinstance(value, bytes):
        payload = value
    else:
        raise TypeError("artifact digest input must be text or bytes")
    return hashlib.sha256(payload).hexdigest()


def validate_case_contract(case: Mapping[str, Any]) -> dict[str, Any]:
    issues: list[ValidationIssue] = []
    if not isinstance(case, Mapping):
        _raise_single("case", "type", "$", "case must be an object")

    _check_keys(
        case,
        required={
            "schema_version",
            "case_id",
            "split",
            "artifacts",
            "recovery",
            "policy",
        },
        allowed={
            "schema_version",
            "case_id",
            "split",
            "artifacts",
            "recovery",
            "policy",
        },
        path="$",
        issues=issues,
    )
    _check_const(
        case.get("schema_version"), CASE_SCHEMA_VERSION, "$.schema_version", issues
    )
    _check_identifier(case.get("case_id"), "$.case_id", issues)
    _check_enum(case.get("split"), CASE_SPLITS, "$.split", issues)

    artifacts = case.get("artifacts")
    artifact_ids: set[str] = set()
    if not _is_array(artifacts) or not artifacts:
        issues.append(
            ValidationIssue("type", "$.artifacts", "artifacts must be a non-empty array")
        )
    else:
        for index, artifact in enumerate(artifacts):
            path = f"$.artifacts[{index}]"
            if not isinstance(artifact, Mapping):
                issues.append(ValidationIssue("type", path, "artifact must be an object"))
                continue
            _check_keys(
                artifact,
                required={"artifact_id", "kind", "path", "authority"},
                allowed={"artifact_id", "kind", "path", "authority"},
                path=path,
                issues=issues,
            )
            artifact_id = artifact.get("artifact_id")
            _check_identifier(artifact_id, f"{path}.artifact_id", issues)
            if isinstance(artifact_id, str):
                if artifact_id in artifact_ids:
                    issues.append(
                        ValidationIssue(
                            "duplicate",
                            f"{path}.artifact_id",
                            "artifact_id must be unique",
                        )
                    )
                artifact_ids.add(artifact_id)
                if artifact_id.casefold() == "oracle":
                    issues.append(
                        ValidationIssue(
                            "reserved",
                            f"{path}.artifact_id",
                            "reserved evaluation data cannot be a case artifact",
                        )
                    )
            kind = artifact.get("kind")
            authority = artifact.get("authority")
            _check_enum(kind, ARTIFACT_KINDS, f"{path}.kind", issues)
            _check_enum(authority, ARTIFACT_AUTHORITIES, f"{path}.authority", issues)
            _check_artifact_authority(kind, authority, path, issues)
            _check_relative_path(artifact.get("path"), f"{path}.path", issues)

    _validate_recovery_config(case.get("recovery"), "$.recovery", issues)
    _validate_policy(case.get("policy"), "$.policy", issues)
    _check_json_compatible(case, "$", issues)
    _finish("case", issues)
    return dict(case)


def validate_semantic_contract(
    semantic_output: Mapping[str, Any], *, case_id: str | None = None
) -> dict[str, Any]:
    issues: list[ValidationIssue] = []
    _validate_semantic_envelope(semantic_output, case_id, issues)
    proposals = semantic_output.get("proposals") if isinstance(semantic_output, Mapping) else None
    proposal_ids: set[str] = set()
    if _is_array(proposals):
        for index, proposal in enumerate(proposals):
            path = f"$.proposals[{index}]"
            candidate_issues = validate_model_proposal_shape(proposal, path=path)
            issues.extend(candidate_issues)
            if isinstance(proposal, Mapping):
                proposal_id = proposal.get("proposal_id")
                if isinstance(proposal_id, str):
                    if proposal_id in proposal_ids:
                        issues.append(
                            ValidationIssue(
                                "duplicate", f"{path}.proposal_id", "proposal_id must be unique"
                            )
                        )
                    proposal_ids.add(proposal_id)
    _check_json_compatible(semantic_output, "$", issues)
    _finish("semantic proposal", issues)
    return dict(semantic_output)


def validate_semantic_envelope(
    semantic_output: Mapping[str, Any], *, case_id: str | None = None
) -> dict[str, Any]:
    issues: list[ValidationIssue] = []
    _validate_semantic_envelope(semantic_output, case_id, issues)
    _check_json_compatible(semantic_output, "$", issues)
    _finish("semantic proposal envelope", issues)
    return dict(semantic_output)


def validate_model_proposal_shape(
    proposal: Any, *, path: str = "$.proposal"
) -> tuple[ValidationIssue, ...]:
    return _validate_proposal_shape(proposal, path=path, model_facing=True)


def validate_proposal_shape(
    proposal: Any, *, path: str = "$.proposal"
) -> tuple[ValidationIssue, ...]:
    return _validate_proposal_shape(proposal, path=path, model_facing=False)


def _validate_proposal_shape(
    proposal: Any, *, path: str, model_facing: bool
) -> tuple[ValidationIssue, ...]:
    issues: list[ValidationIssue] = []
    if not isinstance(proposal, Mapping):
        return (ValidationIssue("type", path, "proposal must be an object"),)

    _check_keys(
        proposal,
        required={
            "proposal_id",
            "relation_type",
            "subject",
            "object",
            "citations",
        },
        allowed={
            "proposal_id",
            "relation_type",
            "subject",
            "object",
            "citations",
            "probe_id",
        },
        path=path,
        issues=issues,
    )
    _check_identifier(proposal.get("proposal_id"), f"{path}.proposal_id", issues)
    relation_type = proposal.get("relation_type")
    _check_enum(relation_type, RELATION_TYPES, f"{path}.relation_type", issues)
    _check_nonempty_text(proposal.get("subject"), f"{path}.subject", issues)
    _check_nonempty_text(proposal.get("object"), f"{path}.object", issues)

    probe_id = proposal.get("probe_id")
    if relation_type == "probe_selection":
        if "probe_id" not in proposal:
            issues.append(
                ValidationIssue(
                    "required", f"{path}.probe_id", "probe_selection requires probe_id"
                )
            )
        else:
            _check_enum(probe_id, PROBE_IDS, f"{path}.probe_id", issues)
    elif "probe_id" in proposal:
        issues.append(
            ValidationIssue(
                "forbidden",
                f"{path}.probe_id",
                "only probe_selection may include probe_id",
            )
        )

    citations = proposal.get("citations")
    if not _is_array(citations) or not citations:
        issues.append(
            ValidationIssue(
                "type", f"{path}.citations", "citations must be a non-empty array"
            )
        )
    else:
        seen_citations: set[str] = set()
        for index, citation in enumerate(citations):
            citation_path = f"{path}.citations[{index}]"
            citation_shape = (
                validate_model_citation_shape
                if model_facing
                else validate_citation_shape
            )
            issues.extend(citation_shape(citation, path=citation_path))
            if isinstance(citation, Mapping):
                identity = (
                    citation.get("artifact_id"),
                    citation.get("quote"),
                )
                if not model_facing:
                    identity = (
                        citation.get("artifact_id"),
                        citation.get("digest"),
                        citation.get("start"),
                        citation.get("end"),
                        citation.get("quote"),
                    )
                identity_key = repr(identity)
                if identity_key in seen_citations:
                    issues.append(
                        ValidationIssue(
                            "duplicate", citation_path, "citations must be unique"
                        )
                    )
                seen_citations.add(identity_key)
    return tuple(issues)


def validate_model_citation_shape(
    citation: Any, *, path: str = "$.citation"
) -> tuple[ValidationIssue, ...]:
    issues: list[ValidationIssue] = []
    if not isinstance(citation, Mapping):
        return (ValidationIssue("type", path, "citation must be an object"),)
    _check_keys(
        citation,
        required={"artifact_id", "quote"},
        allowed={"artifact_id", "quote"},
        path=path,
        issues=issues,
    )
    _check_identifier(citation.get("artifact_id"), f"{path}.artifact_id", issues)
    _check_nonempty_text(citation.get("quote"), f"{path}.quote", issues)
    return tuple(issues)


def validate_citation_shape(
    citation: Any, *, path: str = "$.citation"
) -> tuple[ValidationIssue, ...]:
    issues: list[ValidationIssue] = []
    if not isinstance(citation, Mapping):
        return (ValidationIssue("type", path, "citation must be an object"),)
    _check_keys(
        citation,
        required={"artifact_id", "digest", "start", "end", "quote"},
        allowed={"artifact_id", "digest", "start", "end", "quote"},
        path=path,
        issues=issues,
    )
    _check_identifier(citation.get("artifact_id"), f"{path}.artifact_id", issues)
    digest = citation.get("digest")
    if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
        issues.append(
            ValidationIssue(
                "digest_format",
                f"{path}.digest",
                "digest must be a lowercase SHA-256 hexadecimal value",
            )
        )
    _check_nonnegative_integer(citation.get("start"), f"{path}.start", issues)
    _check_nonnegative_integer(citation.get("end"), f"{path}.end", issues)
    start = citation.get("start")
    end = citation.get("end")
    if _is_integer(start) and _is_integer(end) and end <= start:
        issues.append(
            ValidationIssue(
                "citation_bounds", f"{path}.end", "end must be greater than start"
            )
        )
    _check_nonempty_text(citation.get("quote"), f"{path}.quote", issues)
    return tuple(issues)


def validate_citation(
    citation: Mapping[str, Any],
    artifact_texts: Mapping[str, str | bytes],
    *,
    allowed_artifact_ids: set[str] | frozenset[str] | None = None,
    path: str = "$.citation",
) -> dict[str, Any]:
    issues = list(validate_citation_shape(citation, path=path))
    if issues:
        _finish("citation", issues)

    artifact_id = citation["artifact_id"]
    if allowed_artifact_ids is not None and artifact_id not in allowed_artifact_ids:
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
        _finish("citation", issues)

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
            _finish("citation", issues)
            raise AssertionError("unreachable")
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
            _finish("citation", issues)
            raise AssertionError("unreachable")
    else:
        issues.append(
            ValidationIssue(
                "artifact_type",
                f"{path}.artifact_id",
                "artifact text must be text or bytes",
            )
        )
        _finish("citation", issues)
        raise AssertionError("unreachable")

    actual_digest = hashlib.sha256(payload).hexdigest()
    if citation["digest"] != actual_digest:
        issues.append(
            ValidationIssue(
                "artifact_digest_mismatch",
                f"{path}.digest",
                "citation digest does not match the complete artifact",
            )
        )
    start = citation["start"]
    end = citation["end"]
    if start > len(text) or end > len(text):
        issues.append(
            ValidationIssue(
                "citation_bounds", path, "citation offsets exceed artifact character bounds"
            )
        )
    elif text[start:end] != citation["quote"]:
        issues.append(
            ValidationIssue(
                "citation_quote_mismatch",
                f"{path}.quote",
                "quote does not exactly match the cited character span",
            )
        )
    _finish("citation", issues)
    return dict(citation)


def load_artifact_texts(
    case: Mapping[str, Any], case_directory: str | Path
) -> dict[str, str]:
    validated = validate_case_contract(case)
    root = Path(case_directory).resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)

    texts: dict[str, str] = {}
    for artifact in validated["artifacts"]:
        artifact_path = (root / artifact["path"]).resolve(strict=True)
        try:
            artifact_path.relative_to(root)
        except ValueError as exc:
            raise ValueError("artifact path resolves outside the case directory") from exc
        payload = artifact_path.read_bytes()
        try:
            texts[artifact["artifact_id"]] = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError(f"artifact {artifact['artifact_id']} is not valid UTF-8") from exc
    return texts


def validate_recovery_result(
    recovery: Mapping[str, Any], *, path: str = "$.recovery"
) -> dict[str, Any]:
    issues: list[ValidationIssue] = []
    _validate_recovery_result(recovery, path, issues)
    _check_json_compatible(recovery, path, issues)
    _finish("recovery result", issues)
    return dict(recovery)


def validate_evidence_packet(
    packet: Mapping[str, Any],
    *,
    case: Mapping[str, Any] | None = None,
    artifact_texts: Mapping[str, str | bytes] | None = None,
) -> dict[str, Any]:
    issues: list[ValidationIssue] = []
    if not isinstance(packet, Mapping):
        _raise_single("evidence packet", "type", "$", "packet must be an object")
    required = {
        "schema_version",
        "case_id",
        "arm",
        "facts",
        "derivations",
        "semantic",
        "advisory",
        "unknowns",
        "blockers",
        "recovery",
        "human_decision_state",
        "semantic_status",
    }
    _check_keys(packet, required=required, allowed=required, path="$", issues=issues)
    _check_const(
        packet.get("schema_version"),
        EVIDENCE_PACKET_SCHEMA_VERSION,
        "$.schema_version",
        issues,
    )
    _check_identifier(packet.get("case_id"), "$.case_id", issues)
    _check_identifier(packet.get("arm"), "$.arm", issues)
    _validate_records(
        packet.get("facts"),
        "$.facts",
        required={"fact_id", "kind", "value", "source"},
        allowed={"fact_id", "kind", "value", "source"},
        id_key="fact_id",
        issues=issues,
    )
    _validate_records(
        packet.get("derivations"),
        "$.derivations",
        required={"derivation_id", "kind", "value", "evidence_refs"},
        allowed={"derivation_id", "kind", "value", "evidence_refs"},
        id_key="derivation_id",
        issues=issues,
        refs_key="evidence_refs",
    )
    _validate_semantic_resolution(packet.get("semantic"), "$.semantic", issues)
    _validate_records(
        packet.get("advisory"),
        "$.advisory",
        required={"advisory_id", "kind", "value", "evidence_refs"},
        allowed={"advisory_id", "kind", "value", "evidence_refs"},
        id_key="advisory_id",
        issues=issues,
        refs_key="evidence_refs",
    )
    _validate_unknowns(packet.get("unknowns"), "$.unknowns", issues)
    _validate_blockers(packet.get("blockers"), "$.blockers", issues)
    _validate_recovery_result(packet.get("recovery"), "$.recovery", issues)
    _check_enum(
        packet.get("human_decision_state"),
        HUMAN_DECISION_STATES,
        "$.human_decision_state",
        issues,
    )
    semantic_status = packet.get("semantic_status")
    _check_enum(semantic_status, SEMANTIC_STATUSES, "$.semantic_status", issues)

    validated_case: dict[str, Any] | None = None
    if case is not None:
        try:
            validated_case = validate_case_contract(case)
        except ProtocolValidationError as exc:
            issues.extend(
                ValidationIssue(issue.code, f"$.case{issue.path[1:]}", issue.message)
                for issue in exc.issues
            )
        else:
            if packet.get("case_id") != validated_case["case_id"]:
                issues.append(
                    ValidationIssue(
                        "case_id_mismatch",
                        "$.case_id",
                        "packet case_id does not match the case contract",
                    )
                )

    semantic = packet.get("semantic")
    admitted = semantic.get("admitted", []) if isinstance(semantic, Mapping) else []
    rejected = semantic.get("rejected", []) if isinstance(semantic, Mapping) else []
    abstained = semantic.get("abstained") if isinstance(semantic, Mapping) else None
    requested = (
        semantic.get("requested_evidence", []) if isinstance(semantic, Mapping) else []
    )
    if semantic_status == "not_requested":
        if admitted or rejected or requested or abstained is not False:
            issues.append(
                ValidationIssue(
                    "semantic_state",
                    "$.semantic",
                    "not_requested semantic state must be empty and not abstained",
                )
            )
    elif semantic_status == "unavailable":
        if admitted:
            issues.append(
                ValidationIssue(
                    "semantic_state",
                    "$.semantic.admitted",
                    "unavailable semantic output cannot contain admitted proposals",
                )
            )
        if abstained is not True:
            issues.append(
                ValidationIssue(
                    "semantic_state",
                    "$.semantic.abstained",
                    "unavailable semantic output must preserve abstention",
                )
            )
    if admitted and artifact_texts is None:
        issues.append(
            ValidationIssue(
                "artifacts_required",
                "$.semantic.admitted",
                "artifact text is required to validate admitted citations",
            )
        )
    elif admitted and artifact_texts is not None:
        declared_ids = None
        if validated_case is not None:
            declared_ids = frozenset(
                artifact["artifact_id"] for artifact in validated_case["artifacts"]
            )
        for proposal_index, proposal in enumerate(admitted):
            if not isinstance(proposal, Mapping):
                continue
            for citation_index, citation in enumerate(proposal.get("citations", [])):
                if not isinstance(citation, Mapping):
                    continue
                try:
                    validate_citation(
                        citation,
                        artifact_texts,
                        allowed_artifact_ids=declared_ids,
                        path=(
                            f"$.semantic.admitted[{proposal_index}]"
                            f".citations[{citation_index}]"
                        ),
                    )
                except ProtocolValidationError as exc:
                    issues.extend(exc.issues)

    blockers = packet.get("blockers")
    unknowns = packet.get("unknowns")
    human_state = packet.get("human_decision_state")
    candidate_ids = {
        proposal.get("proposal_id")
        for proposal in admitted
        if isinstance(proposal, Mapping)
        and proposal.get("evidence_class") == "candidate_inference"
        and isinstance(proposal.get("proposal_id"), str)
    }
    blocker_rows = blockers if _is_array(blockers) else []
    unknown_rows = unknowns if _is_array(unknowns) else []
    if human_state == "ready_for_human_decision" and (blocker_rows or unknown_rows or candidate_ids):
        issues.append(
            ValidationIssue(
                "human_state",
                "$.human_decision_state",
                "a packet with blockers, unknowns, or candidate inferences cannot be decision-ready",
            )
        )
    if human_state == "blocked" and not blocker_rows:
        issues.append(
            ValidationIssue(
                "human_state",
                "$.human_decision_state",
                "a blocked packet must contain a deterministic blocker",
            )
        )
    if human_state == "needs_confirmation" and not (blocker_rows or candidate_ids):
        issues.append(
            ValidationIssue(
                "human_state",
                "$.human_decision_state",
                "confirmation state requires a candidate inference or confirmation blocker",
            )
        )
    if semantic_status == "available" and abstained is True:
        semantic_confirmation = any(
            isinstance(blocker, Mapping)
            and blocker.get("code") == "SEMANTIC_CONFIRMATION_REQUIRED"
            and "semantic:abstention" in blocker.get("evidence_refs", [])
            for blocker in blocker_rows
        )
        if not semantic_confirmation:
            issues.append(
                ValidationIssue(
                    "abstention_not_fail_closed",
                    "$.blockers",
                    "an available semantic abstention must require human confirmation",
                )
            )

    recovery = packet.get("recovery")
    if isinstance(recovery, Mapping):
        recovery_statuses = [
            section.get("status")
            for name in ("restore", "canary", "rpo", "rto", "cleanup")
            if isinstance((section := recovery.get(name)), Mapping)
        ]
        if any(status in {"fail", "unknown"} for status in recovery_statuses) and human_state == "ready_for_human_decision":
            issues.append(
                ValidationIssue(
                    "recovery_not_fail_closed",
                    "$.human_decision_state",
                    "failed or unknown recovery evidence cannot be decision-ready",
                )
            )

    _enforce_non_authoritative_semantics(packet, issues)
    _check_json_compatible(packet, "$", issues)
    _finish("evidence packet", issues)
    return dict(packet)


def _assert_json_value(value: Any, path: str = "$") -> None:
    if not isinstance(value, _JSON_TYPES):
        raise TypeError(f"{path} has non-JSON type {type(value).__name__}")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{path} must not contain NaN or infinity")
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError(f"{path} must contain valid Unicode") from exc
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_json_value(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} object keys must be strings")
            _assert_json_value(item, f"{path}.{key}")


def _check_json_compatible(
    value: Any, path: str, issues: list[ValidationIssue]
) -> None:
    try:
        _assert_json_value(value, path)
    except (TypeError, ValueError) as exc:
        issues.append(ValidationIssue("json_type", path, str(exc)))


def _validate_semantic_envelope(
    semantic_output: Any,
    case_id: str | None,
    issues: list[ValidationIssue],
) -> None:
    if not isinstance(semantic_output, Mapping):
        issues.append(ValidationIssue("type", "$", "semantic output must be an object"))
        return
    required = {
        "schema_version",
        "case_id",
        "proposals",
        "abstained",
        "requested_evidence",
    }
    _check_keys(
        semantic_output, required=required, allowed=required, path="$", issues=issues
    )
    _check_const(
        semantic_output.get("schema_version"),
        SEMANTIC_SCHEMA_VERSION,
        "$.schema_version",
        issues,
    )
    _check_identifier(semantic_output.get("case_id"), "$.case_id", issues)
    if case_id is not None and semantic_output.get("case_id") != case_id:
        issues.append(
            ValidationIssue(
                "case_id_mismatch", "$.case_id", "semantic output is bound to another case"
            )
        )
    proposals = semantic_output.get("proposals")
    if not _is_array(proposals):
        issues.append(
            ValidationIssue("type", "$.proposals", "proposals must be an array")
        )
    abstained = semantic_output.get("abstained")
    if not isinstance(abstained, bool):
        issues.append(
            ValidationIssue("type", "$.abstained", "abstained must be a boolean")
        )
    requested = semantic_output.get("requested_evidence")
    if not _is_array(requested):
        issues.append(
            ValidationIssue(
                "type", "$.requested_evidence", "requested_evidence must be an array"
            )
        )
    else:
        _check_unique_nonempty_strings(requested, "$.requested_evidence", issues)
    if abstained is True and _is_array(requested) and not requested:
        issues.append(
            ValidationIssue(
                "evidence_request_required",
                "$.requested_evidence",
                "abstention must request specific evidence",
            )
        )


def _validate_recovery_config(
    recovery: Any, path: str, issues: list[ValidationIssue]
) -> None:
    if not isinstance(recovery, Mapping):
        issues.append(ValidationIssue("type", path, "recovery must be an object"))
        return
    required = {
        "dump_path",
        "backup_created_at",
        "reference_time",
        "rpo_seconds",
        "rto_ms",
        "minimum_delay_ms",
        "expected_schema_version",
        "required_tables",
        "assertions",
    }
    allowed = required | {"simulate_cleanup_failure"}
    _check_keys(recovery, required=required, allowed=allowed, path=path, issues=issues)
    _check_relative_path(recovery.get("dump_path"), f"{path}.dump_path", issues)
    _check_iso8601(recovery.get("backup_created_at"), f"{path}.backup_created_at", issues)
    _check_iso8601(recovery.get("reference_time"), f"{path}.reference_time", issues)
    for key in (
        "rpo_seconds",
        "rto_ms",
        "minimum_delay_ms",
        "expected_schema_version",
    ):
        _check_nonnegative_integer(recovery.get(key), f"{path}.{key}", issues)
    required_tables = recovery.get("required_tables")
    if not _is_array(required_tables) or not required_tables:
        issues.append(
            ValidationIssue(
                "type", f"{path}.required_tables", "required_tables must be a non-empty array"
            )
        )
    else:
        _check_unique_nonempty_strings(
            required_tables, f"{path}.required_tables", issues
        )
    assertions = recovery.get("assertions")
    if not _is_array(assertions):
        issues.append(
            ValidationIssue("type", f"{path}.assertions", "assertions must be an array")
        )
    else:
        assertion_ids: set[str] = set()
        for index, assertion in enumerate(assertions):
            assertion_path = f"{path}.assertions[{index}]"
            if not isinstance(assertion, Mapping):
                issues.append(
                    ValidationIssue("type", assertion_path, "assertion must be an object")
                )
                continue
            _check_keys(
                assertion,
                required={"assertion_id", "sql", "expected"},
                allowed={"assertion_id", "sql", "expected"},
                path=assertion_path,
                issues=issues,
            )
            assertion_id = assertion.get("assertion_id")
            _check_identifier(assertion_id, f"{assertion_path}.assertion_id", issues)
            if isinstance(assertion_id, str):
                if assertion_id in assertion_ids:
                    issues.append(
                        ValidationIssue(
                            "duplicate",
                            f"{assertion_path}.assertion_id",
                            "assertion_id must be unique",
                        )
                    )
                assertion_ids.add(assertion_id)
            _check_nonempty_text(assertion.get("sql"), f"{assertion_path}.sql", issues)
    if "simulate_cleanup_failure" in recovery and not isinstance(
        recovery.get("simulate_cleanup_failure"), bool
    ):
        issues.append(
            ValidationIssue(
                "type",
                f"{path}.simulate_cleanup_failure",
                "simulate_cleanup_failure must be a boolean",
            )
        )


def _validate_policy(policy: Any, path: str, issues: list[ValidationIssue]) -> None:
    if not isinstance(policy, Mapping):
        issues.append(ValidationIssue("type", path, "policy must be an object"))
        return
    required = {
        "reference_time",
        "max_evidence_age_seconds",
        "allowed_probe_ids",
        "required_owner_fields",
        "human_decision_required",
    }
    _check_keys(policy, required=required, allowed=required, path=path, issues=issues)
    _check_iso8601(policy.get("reference_time"), f"{path}.reference_time", issues)
    _check_nonnegative_integer(
        policy.get("max_evidence_age_seconds"),
        f"{path}.max_evidence_age_seconds",
        issues,
    )
    probes = policy.get("allowed_probe_ids")
    if not _is_array(probes):
        issues.append(
            ValidationIssue(
                "type", f"{path}.allowed_probe_ids", "allowed_probe_ids must be an array"
            )
        )
    else:
        _check_unique_nonempty_strings(probes, f"{path}.allowed_probe_ids", issues)
        for index, probe in enumerate(probes):
            _check_enum(probe, PROBE_IDS, f"{path}.allowed_probe_ids[{index}]", issues)
    owner_fields = policy.get("required_owner_fields")
    if not _is_array(owner_fields):
        issues.append(
            ValidationIssue(
                "type",
                f"{path}.required_owner_fields",
                "required_owner_fields must be an array",
            )
        )
    else:
        _check_unique_nonempty_strings(
            owner_fields, f"{path}.required_owner_fields", issues
        )
        missing = {"owner", "recovery_owner"} - {
            item for item in owner_fields if isinstance(item, str)
        }
        if missing:
            issues.append(
                ValidationIssue(
                    "required_value",
                    f"{path}.required_owner_fields",
                    "required_owner_fields must contain owner and recovery_owner",
                )
            )
    _check_const(
        policy.get("human_decision_required"),
        True,
        f"{path}.human_decision_required",
        issues,
    )


def _validate_recovery_result(
    recovery: Any, path: str, issues: list[ValidationIssue]
) -> None:
    if not isinstance(recovery, Mapping):
        issues.append(ValidationIssue("type", path, "recovery must be an object"))
        return
    required = {
        "restore",
        "canary",
        "rpo",
        "rto",
        "cleanup",
        "classification",
        "timing",
    }
    _check_keys(recovery, required=required, allowed=required, path=path, issues=issues)

    restore = recovery.get("restore")
    _validate_status_object(
        restore,
        f"{path}.restore",
        extra_required={"elapsed_ms"},
        nullable_nonnegative={"elapsed_ms"},
        issues=issues,
    )
    canary = recovery.get("canary")
    if not isinstance(canary, Mapping):
        issues.append(ValidationIssue("type", f"{path}.canary", "canary must be an object"))
    else:
        _check_keys(
            canary,
            required={"status", "checks"},
            allowed={"status", "checks"},
            path=f"{path}.canary",
            issues=issues,
        )
        _check_enum(canary.get("status"), RECOVERY_STATUSES, f"{path}.canary.status", issues)
        checks = canary.get("checks")
        if not _is_array(checks) or not checks:
            issues.append(
                ValidationIssue(
                    "type",
                    f"{path}.canary.checks",
                    "checks must be a non-empty array",
                )
            )
        else:
            _validate_canary_checks(checks, f"{path}.canary.checks", issues)

    rpo = recovery.get("rpo")
    _validate_status_object(
        rpo,
        f"{path}.rpo",
        extra_required={"age_seconds", "objective_seconds"},
        nullable_nonnegative={"age_seconds"},
        nonnegative={"objective_seconds"},
        issues=issues,
    )
    rto = recovery.get("rto")
    _validate_status_object(
        rto,
        f"{path}.rto",
        extra_required={"elapsed_ms", "objective_ms"},
        nullable_nonnegative={"elapsed_ms"},
        nonnegative={"objective_ms"},
        issues=issues,
    )
    cleanup = recovery.get("cleanup")
    _validate_status_object(cleanup, f"{path}.cleanup", issues=issues)
    classification = recovery.get("classification")
    _check_enum(classification, RECOVERY_STATUSES, f"{path}.classification", issues)

    statuses: list[str] = []
    for section in (restore, canary, rpo, rto, cleanup):
        if isinstance(section, Mapping) and section.get("status") in RECOVERY_STATUSES:
            statuses.append(section["status"])
    if len(statuses) == 5 and classification in RECOVERY_STATUSES:
        expected = _aggregate_statuses(statuses)
        if classification != expected:
            issues.append(
                ValidationIssue(
                    "classification_mismatch",
                    f"{path}.classification",
                    "classification must be derived from deterministic section statuses",
                )
            )

    if isinstance(canary, Mapping) and _is_array(canary.get("checks")):
        check_statuses = [
            check.get("status")
            for check in canary["checks"]
            if isinstance(check, Mapping) and check.get("status") in RECOVERY_STATUSES
        ]
        if check_statuses and canary.get("status") in RECOVERY_STATUSES:
            expected_canary = _aggregate_statuses(check_statuses)
            if canary.get("status") != expected_canary:
                issues.append(
                    ValidationIssue(
                        "canary_status_mismatch",
                        f"{path}.canary.status",
                        "canary status must be derived from its deterministic checks",
                    )
                )

    _validate_objective_comparison(
        rpo,
        value_key="age_seconds",
        objective_key="objective_seconds",
        path=f"{path}.rpo",
        issues=issues,
    )
    _validate_objective_comparison(
        rto,
        value_key="elapsed_ms",
        objective_key="objective_ms",
        path=f"{path}.rto",
        issues=issues,
    )
    _validate_timing_transcript(
        recovery.get("timing"),
        restore=restore,
        rto=rto,
        path=f"{path}.timing",
        issues=issues,
    )


def _validate_timing_transcript(
    timing: Any,
    *,
    restore: Any,
    rto: Any,
    path: str,
    issues: list[ValidationIssue],
) -> None:
    if not isinstance(timing, Mapping):
        issues.append(ValidationIssue("type", path, "timing must be an object"))
        return
    sample_keys = (
        "rto_started_ns",
        "restore_started_ns",
        "restore_completed_ns",
        "rto_completed_ns",
    )
    required = {"clock", *sample_keys}
    _check_keys(
        timing,
        required=required,
        allowed=required,
        path=path,
        issues=issues,
    )
    clock = timing.get("clock")
    if clock == "unavailable":
        for key in sample_keys:
            if timing.get(key) is not None:
                issues.append(
                    ValidationIssue(
                        "timing_unavailable",
                        f"{path}.{key}",
                        "unavailable timing cannot contain clock samples",
                    )
                )
        for section, section_name in ((restore, "restore"), (rto, "rto")):
            if isinstance(section, Mapping) and (
                section.get("status") != "unknown"
                or section.get("elapsed_ms") is not None
            ):
                issues.append(
                    ValidationIssue(
                        "timing_unavailable",
                        path,
                        f"unavailable timing requires unknown {section_name} evidence",
                    )
                )
        return
    if clock != "monotonic_ns":
        issues.append(
            ValidationIssue(
                "enum", f"{path}.clock", "clock must be monotonic_ns or unavailable"
            )
        )
        return

    valid_samples = True
    for key in sample_keys:
        value = timing.get(key)
        if not _is_integer(value) or value < 0:
            valid_samples = False
            issues.append(
                ValidationIssue(
                    "type", f"{path}.{key}", "clock samples must be nonnegative integers"
                )
            )
    if not valid_samples:
        return

    rto_started = timing["rto_started_ns"]
    restore_started = timing["restore_started_ns"]
    restore_completed = timing["restore_completed_ns"]
    rto_completed = timing["rto_completed_ns"]
    if not (
        rto_started
        <= restore_started
        <= restore_completed
        <= rto_completed
    ):
        issues.append(
            ValidationIssue(
                "timing_order",
                path,
                "timing samples must preserve RTO and restore phase ordering",
            )
        )
        return

    expected_restore_ms = round((restore_completed - restore_started) / 1_000_000, 3)
    expected_rto_ms = round((rto_completed - rto_started) / 1_000_000, 3)
    for section, section_name, expected in (
        (restore, "restore", expected_restore_ms),
        (rto, "rto", expected_rto_ms),
    ):
        if not isinstance(section, Mapping) or section.get("elapsed_ms") != expected:
            issues.append(
                ValidationIssue(
                    "timing_delta",
                    f"{path}.{section_name}",
                    f"{section_name} elapsed_ms must be derived from monotonic samples",
                )
            )
    if expected_restore_ms > expected_rto_ms:
        issues.append(
            ValidationIssue(
                "timing_containment",
                path,
                "restore duration cannot exceed the enclosing RTO duration",
            )
        )


def _validate_objective_comparison(
    section: Any,
    *,
    value_key: str,
    objective_key: str,
    path: str,
    issues: list[ValidationIssue],
) -> None:
    if not isinstance(section, Mapping):
        return
    status = section.get("status")
    value = section.get(value_key)
    objective = section.get(objective_key)
    if status not in {"pass", "fail"}:
        return
    if (
        isinstance(value, bool)
        or isinstance(objective, bool)
        or not isinstance(value, (int, float))
        or not isinstance(objective, (int, float))
    ):
        issues.append(
            ValidationIssue(
                "objective_comparison",
                path,
                "pass/fail objective evidence requires numeric measured and objective values",
            )
        )
        return
    expected = "pass" if value <= objective else "fail"
    if status != expected:
        issues.append(
            ValidationIssue(
                "objective_comparison",
                f"{path}.status",
                "objective status does not match the measured comparison",
            )
        )


def _validate_status_object(
    value: Any,
    path: str,
    *,
    extra_required: set[str] | None = None,
    nullable_nonnegative: set[str] | None = None,
    nonnegative: set[str] | None = None,
    issues: list[ValidationIssue],
) -> None:
    if not isinstance(value, Mapping):
        issues.append(ValidationIssue("type", path, "section must be an object"))
        return
    extras = extra_required or set()
    required = {"status"} | extras
    _check_keys(value, required=required, allowed=required, path=path, issues=issues)
    _check_enum(value.get("status"), RECOVERY_STATUSES, f"{path}.status", issues)
    for key in nullable_nonnegative or set():
        item = value.get(key)
        if item is not None:
            _check_nonnegative_number(item, f"{path}.{key}", issues)
    for key in nonnegative or set():
        _check_nonnegative_number(value.get(key), f"{path}.{key}", issues)


def _validate_canary_checks(
    checks: Sequence[Any], path: str, issues: list[ValidationIssue]
) -> None:
    check_ids: set[str] = set()
    statuses: list[str] = []
    for index, check in enumerate(checks):
        item_path = f"{path}[{index}]"
        if not isinstance(check, Mapping):
            issues.append(ValidationIssue("type", item_path, "check must be an object"))
            continue
        required = {"check_id", "check_type", "status"}
        allowed = required | {"assertion_id", "expected", "actual"}
        _check_keys(check, required=required, allowed=allowed, path=item_path, issues=issues)
        check_id = check.get("check_id")
        _check_identifier(check_id, f"{item_path}.check_id", issues)
        if isinstance(check_id, str):
            if check_id in check_ids:
                issues.append(
                    ValidationIssue(
                        "duplicate", f"{item_path}.check_id", "check_id must be unique"
                    )
                )
            check_ids.add(check_id)
        _check_enum(check.get("check_type"), CANARY_CHECK_TYPES, f"{item_path}.check_type", issues)
        _check_enum(check.get("status"), RECOVERY_STATUSES, f"{item_path}.status", issues)
        if check.get("status") in RECOVERY_STATUSES:
            statuses.append(check["status"])
        if "assertion_id" in check:
            _check_identifier(check.get("assertion_id"), f"{item_path}.assertion_id", issues)
        if ("expected" in check) != ("actual" in check):
            issues.append(
                ValidationIssue(
                    "paired_fields",
                    item_path,
                    "expected and actual must either both be present or both be absent",
                )
            )


def _validate_semantic_resolution(
    semantic: Any, path: str, issues: list[ValidationIssue]
) -> None:
    if not isinstance(semantic, Mapping):
        issues.append(ValidationIssue("type", path, "semantic must be an object"))
        return
    required = {"admitted", "rejected", "abstained", "requested_evidence"}
    _check_keys(semantic, required=required, allowed=required, path=path, issues=issues)
    admitted = semantic.get("admitted")
    if not _is_array(admitted):
        issues.append(
            ValidationIssue("type", f"{path}.admitted", "admitted must be an array")
        )
    else:
        proposal_ids: set[str] = set()
        for index, proposal in enumerate(admitted):
            proposal_path = f"{path}.admitted[{index}]"
            if not isinstance(proposal, Mapping):
                issues.append(
                    ValidationIssue("type", proposal_path, "admitted proposal must be an object")
                )
                continue
            base = dict(proposal)
            evidence_class = base.pop("evidence_class", None)
            issues.extend(validate_proposal_shape(base, path=proposal_path))
            relation_type = proposal.get("relation_type")
            expected_class = RELATION_EVIDENCE_CLASSES.get(relation_type)
            if evidence_class != expected_class:
                issues.append(
                    ValidationIssue(
                        "evidence_class",
                        f"{proposal_path}.evidence_class",
                        "evidence_class must be assigned by the relation allowlist",
                    )
                )
            proposal_id = proposal.get("proposal_id")
            if isinstance(proposal_id, str):
                if proposal_id in proposal_ids:
                    issues.append(
                        ValidationIssue(
                            "duplicate",
                            f"{proposal_path}.proposal_id",
                            "admitted proposal_id must be unique",
                        )
                    )
                proposal_ids.add(proposal_id)
    rejected = semantic.get("rejected")
    if not _is_array(rejected):
        issues.append(
            ValidationIssue("type", f"{path}.rejected", "rejected must be an array")
        )
    else:
        for index, rejection in enumerate(rejected):
            rejection_path = f"{path}.rejected[{index}]"
            if not isinstance(rejection, Mapping):
                issues.append(
                    ValidationIssue("type", rejection_path, "rejection must be an object")
                )
                continue
            _check_keys(
                rejection,
                required={"proposal_id", "reason_codes"},
                allowed={"proposal_id", "reason_codes"},
                path=rejection_path,
                issues=issues,
            )
            _check_nonempty_text(
                rejection.get("proposal_id"), f"{rejection_path}.proposal_id", issues
            )
            reasons = rejection.get("reason_codes")
            if not _is_array(reasons) or not reasons:
                issues.append(
                    ValidationIssue(
                        "type",
                        f"{rejection_path}.reason_codes",
                        "reason_codes must be a non-empty array",
                    )
                )
            else:
                _check_unique_nonempty_strings(
                    reasons, f"{rejection_path}.reason_codes", issues
                )
    if not isinstance(semantic.get("abstained"), bool):
        issues.append(
            ValidationIssue("type", f"{path}.abstained", "abstained must be a boolean")
        )
    requested = semantic.get("requested_evidence")
    if not _is_array(requested):
        issues.append(
            ValidationIssue(
                "type", f"{path}.requested_evidence", "requested_evidence must be an array"
            )
        )
    else:
        _check_unique_nonempty_strings(requested, f"{path}.requested_evidence", issues)


def _validate_records(
    records: Any,
    path: str,
    *,
    required: set[str],
    allowed: set[str],
    id_key: str,
    issues: list[ValidationIssue],
    refs_key: str | None = None,
) -> None:
    if not _is_array(records):
        issues.append(ValidationIssue("type", path, "value must be an array"))
        return
    record_ids: set[str] = set()
    for index, record in enumerate(records):
        record_path = f"{path}[{index}]"
        if not isinstance(record, Mapping):
            issues.append(ValidationIssue("type", record_path, "record must be an object"))
            continue
        _check_keys(
            record, required=required, allowed=allowed, path=record_path, issues=issues
        )
        record_id = record.get(id_key)
        _check_identifier(record_id, f"{record_path}.{id_key}", issues)
        if isinstance(record_id, str):
            if record_id in record_ids:
                issues.append(
                    ValidationIssue(
                        "duplicate", f"{record_path}.{id_key}", f"{id_key} must be unique"
                    )
                )
            record_ids.add(record_id)
        _check_identifier(record.get("kind"), f"{record_path}.kind", issues)
        if id_key == "fact_id":
            _check_nonempty_text(record.get("source"), f"{record_path}.source", issues)
        if refs_key is not None:
            refs = record.get(refs_key)
            if not _is_array(refs):
                issues.append(
                    ValidationIssue(
                        "type", f"{record_path}.{refs_key}", f"{refs_key} must be an array"
                    )
                )
            else:
                _check_unique_nonempty_strings(refs, f"{record_path}.{refs_key}", issues)


def _validate_unknowns(
    unknowns: Any, path: str, issues: list[ValidationIssue]
) -> None:
    if not _is_array(unknowns):
        issues.append(ValidationIssue("type", path, "unknowns must be an array"))
        return
    identities: set[tuple[Any, Any]] = set()
    for index, unknown in enumerate(unknowns):
        item_path = f"{path}[{index}]"
        if not isinstance(unknown, Mapping):
            issues.append(ValidationIssue("type", item_path, "unknown must be an object"))
            continue
        _check_keys(
            unknown,
            required={"code"},
            allowed={"code", "operation_id"},
            path=item_path,
            issues=issues,
        )
        _check_identifier(unknown.get("code"), f"{item_path}.code", issues)
        if "operation_id" in unknown:
            _check_identifier(
                unknown.get("operation_id"), f"{item_path}.operation_id", issues
            )
        identity = (unknown.get("code"), unknown.get("operation_id"))
        if identity in identities:
            issues.append(ValidationIssue("duplicate", item_path, "unknown must be unique"))
        identities.add(identity)


def _validate_blockers(
    blockers: Any, path: str, issues: list[ValidationIssue]
) -> None:
    if not _is_array(blockers):
        issues.append(ValidationIssue("type", path, "blockers must be an array"))
        return
    blocker_ids: set[str] = set()
    for index, blocker in enumerate(blockers):
        item_path = f"{path}[{index}]"
        if not isinstance(blocker, Mapping):
            issues.append(ValidationIssue("type", item_path, "blocker must be an object"))
            continue
        required = {"blocker_id", "code", "message", "evidence_refs", "decision_effect"}
        _check_keys(blocker, required=required, allowed=required, path=item_path, issues=issues)
        blocker_id = blocker.get("blocker_id")
        _check_identifier(blocker_id, f"{item_path}.blocker_id", issues)
        if isinstance(blocker_id, str):
            if blocker_id in blocker_ids:
                issues.append(
                    ValidationIssue(
                        "duplicate", f"{item_path}.blocker_id", "blocker_id must be unique"
                    )
                )
            blocker_ids.add(blocker_id)
        _check_identifier(blocker.get("code"), f"{item_path}.code", issues)
        _check_nonempty_text(blocker.get("message"), f"{item_path}.message", issues)
        refs = blocker.get("evidence_refs")
        if not _is_array(refs) or not refs:
            issues.append(
                ValidationIssue(
                    "type",
                    f"{item_path}.evidence_refs",
                    "blocker evidence_refs must be a non-empty array",
                )
            )
        else:
            _check_unique_nonempty_strings(refs, f"{item_path}.evidence_refs", issues)
        _check_const(blocker.get("decision_effect"), "block", f"{item_path}.decision_effect", issues)


def _enforce_non_authoritative_semantics(
    packet: Mapping[str, Any], issues: list[ValidationIssue]
) -> None:
    semantic = packet.get("semantic")
    admitted = semantic.get("admitted", []) if isinstance(semantic, Mapping) else []
    admitted_ids: set[str] = set()
    non_blocking_ids: set[str] = set()
    if _is_array(admitted):
        for proposal in admitted:
            if not isinstance(proposal, Mapping):
                continue
            proposal_id = proposal.get("proposal_id")
            if isinstance(proposal_id, str):
                admitted_ids.add(proposal_id)
                if proposal.get("relation_type") in {
                    "incident_relevance_advisory",
                    "probe_selection",
                }:
                    non_blocking_ids.add(proposal_id)

    facts = packet.get("facts")
    if _is_array(facts):
        for index, fact in enumerate(facts):
            if isinstance(fact, Mapping) and fact.get("source") in admitted_ids:
                issues.append(
                    ValidationIssue(
                        "semantic_promotion",
                        f"$.facts[{index}].source",
                        "a semantic proposal cannot be promoted to a structured fact",
                    )
                )
    blockers = packet.get("blockers")
    if _is_array(blockers):
        for index, blocker in enumerate(blockers):
            if not isinstance(blocker, Mapping):
                continue
            refs = blocker.get("evidence_refs")
            if _is_array(refs) and non_blocking_ids.intersection(refs):
                issues.append(
                    ValidationIssue(
                        "non_blocking_semantic",
                        f"$.blockers[{index}].evidence_refs",
                        "advisory relevance and probe selection cannot directly support a blocker",
                    )
                )


def _aggregate_statuses(statuses: Sequence[str]) -> str:
    if "fail" in statuses:
        return "fail"
    if "unknown" in statuses:
        return "unknown"
    return "pass"


def _check_artifact_authority(
    kind: Any, authority: Any, path: str, issues: list[ValidationIssue]
) -> None:
    expected: str | None = None
    if kind in {"terraform_plan", "service_manifest", "ownership", "recovery_ledger"}:
        expected = "structured_fact"
    elif kind in {"change_ticket", "change_ticket_text", "pr_description", "runbook"}:
        expected = "declared_context"
    elif kind in {"incident", "history"}:
        expected = "advisory_context"
    if expected is not None and authority != expected:
        issues.append(
            ValidationIssue(
                "authority_mismatch",
                f"{path}.authority",
                f"{kind} artifacts require {expected} authority",
            )
        )


def _check_relative_path(value: Any, path: str, issues: list[ValidationIssue]) -> None:
    if not isinstance(value, str) or not value:
        issues.append(ValidationIssue("type", path, "path must be a non-empty string"))
        return
    if "\x00" in value or "\\" in value:
        issues.append(
            ValidationIssue("unsafe_path", path, "path contains an unsafe character")
        )
        return
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        issues.append(
            ValidationIssue("unsafe_path", path, "path must be normalized and relative")
        )
        return
    if any(part.casefold() == "oracle" or part.casefold() == "oracle.json" for part in candidate.parts):
        issues.append(
            ValidationIssue(
                "reserved", path, "reserved evaluation data must remain outside case artifacts"
            )
        )


def _check_iso8601(value: Any, path: str, issues: list[ValidationIssue]) -> None:
    if not isinstance(value, str) or not value:
        issues.append(
            ValidationIssue("type", path, "timestamp must be a non-empty ISO-8601 string")
        )
        return
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        issues.append(ValidationIssue("timestamp", path, "timestamp is not valid ISO-8601"))
        return
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        issues.append(ValidationIssue("timestamp", path, "timestamp must include a UTC offset"))


def _check_keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    allowed: set[str],
    path: str,
    issues: list[ValidationIssue],
) -> None:
    for key in sorted(required - set(value)):
        issues.append(ValidationIssue("required", f"{path}.{key}", "field is required"))
    for key in sorted(set(value) - allowed):
        issues.append(
            ValidationIssue("additional_property", f"{path}.{key}", "field is not allowed")
        )


def _check_const(
    value: Any, expected: Any, path: str, issues: list[ValidationIssue]
) -> None:
    if value != expected:
        issues.append(
            ValidationIssue("const", path, f"value must be {expected!r}")
        )


def _check_enum(
    value: Any, allowed: frozenset[str], path: str, issues: list[ValidationIssue]
) -> None:
    if not isinstance(value, str) or value not in allowed:
        issues.append(
            ValidationIssue(
                "enum", path, "value is outside the protocol allowlist"
            )
        )


def _check_identifier(value: Any, path: str, issues: list[ValidationIssue]) -> None:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        issues.append(
            ValidationIssue("identifier", path, "value must be a bounded identifier")
        )


def _check_nonempty_text(value: Any, path: str, issues: list[ValidationIssue]) -> None:
    if not isinstance(value, str) or not value.strip():
        issues.append(ValidationIssue("type", path, "value must be non-empty text"))


def _check_nonnegative_integer(
    value: Any, path: str, issues: list[ValidationIssue]
) -> None:
    if not _is_integer(value) or value < 0:
        issues.append(
            ValidationIssue("type", path, "value must be a nonnegative integer")
        )


def _check_nonnegative_number(
    value: Any, path: str, issues: list[ValidationIssue]
) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        issues.append(
            ValidationIssue("type", path, "value must be a nonnegative number")
        )
    elif not math.isfinite(value) or value < 0:
        issues.append(
            ValidationIssue("range", path, "value must be a finite nonnegative number")
        )


def _check_unique_nonempty_strings(
    values: Sequence[Any], path: str, issues: list[ValidationIssue]
) -> None:
    seen: set[str] = set()
    for index, value in enumerate(values):
        item_path = f"{path}[{index}]"
        _check_nonempty_text(value, item_path, issues)
        if isinstance(value, str):
            if value in seen:
                issues.append(ValidationIssue("duplicate", item_path, "value must be unique"))
            seen.add(value)


def _is_array(value: Any) -> bool:
    return isinstance(value, list)


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _finish(contract: str, issues: list[ValidationIssue]) -> None:
    if issues:
        raise ProtocolValidationError(contract, issues)


def _raise_single(contract: str, code: str, path: str, message: str) -> None:
    raise ProtocolValidationError(contract, [ValidationIssue(code, path, message)])
