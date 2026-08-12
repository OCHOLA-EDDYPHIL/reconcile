from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from datetime import datetime, timezone
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path
import re
import unicodedata
from typing import Any


B_ARM_DISABLED_RELATIONS = {
    "b-replay": frozenset(),
    "b-replay-no-alias": frozenset({"resource_alias_candidate"}),
    "b-replay-no-intent": frozenset({"intent_effect_contradiction"}),
    "b-replay-no-probe": frozenset({"probe_selection"}),
    "b-replay-no-incident": frozenset({"incident_relevance_advisory"}),
}
B_ARMS = tuple(B_ARM_DISABLED_RELATIONS)
ARMS = ("a0", "a1", "a1-rules", *B_ARMS)
DESTRUCTIVE_ACTIONS = {"delete"}
SAFE_HUMAN_STATE = "ready_for_human_decision"


class CompilationError(ValueError):
    pass


def _load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_mapping,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise CompilationError(f"cannot load JSON artifact {path}: {exc}") from exc


def _unique_json_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def load_case(case_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    case_dir = Path(case_dir)
    case = _load_json(case_dir / "case.json")
    from lazarus.protocol import validate_case_contract

    case = validate_case_contract(case)
    artifacts: dict[str, Any] = {}
    seen: set[str] = set()
    for entry in case.get("artifacts", []):
        artifact_id = entry.get("artifact_id")
        relative_path = entry.get("path")
        if not isinstance(artifact_id, str) or not artifact_id or artifact_id in seen:
            raise CompilationError("artifact identifiers must be unique non-empty strings")
        if not isinstance(relative_path, str) or not relative_path:
            raise CompilationError(f"artifact {artifact_id} has no path")
        path = (case_dir / relative_path).resolve()
        try:
            path.relative_to(case_dir.resolve())
        except ValueError as exc:
            raise CompilationError(f"artifact {artifact_id} escapes the case directory") from exc
        if not path.is_file():
            raise CompilationError(f"artifact {artifact_id} does not exist")
        raw = path.read_bytes()
        artifacts[artifact_id] = {
            "entry": deepcopy(entry),
            "path": path,
            "raw": raw,
            "digest": hashlib.sha256(raw).hexdigest(),
            "value": _load_json(path) if path.suffix == ".json" else raw.decode("utf-8"),
        }
        seen.add(artifact_id)
    return case, artifacts


def _values_by_kind(case: Mapping[str, Any], artifacts: Mapping[str, Any], kind: str) -> list[Any]:
    values: list[Any] = []
    for entry in case.get("artifacts", []):
        if entry.get("kind") == kind:
            values.append(artifacts[entry["artifact_id"]]["value"])
    return values


def _first_artifact_id(case: Mapping[str, Any], kind: str) -> str:
    for entry in case.get("artifacts", []):
        if isinstance(entry, Mapping) and entry.get("kind") == kind:
            artifact_id = entry.get("artifact_id")
            if isinstance(artifact_id, str):
                return artifact_id
    return kind


def _first_mapping(values: Iterable[Any]) -> dict[str, Any]:
    for value in values:
        if isinstance(value, dict):
            return value
    return {}


def _normal_form(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value)).casefold()
    return " ".join(re.findall(r"[a-z0-9]+", text))


def _tokens(value: Any) -> set[str]:
    return set(_normal_form(value).split())


def _similar(left: Any, right: Any) -> bool:
    left_normal = _normal_form(left)
    right_normal = _normal_form(right)
    if not left_normal or not right_normal:
        return False
    if left_normal == right_normal:
        return True
    shorter, longer = sorted((left_normal, right_normal), key=len)
    if len(shorter) >= 6 and longer.startswith(shorter):
        return True
    left_tokens = _tokens(left_normal)
    right_tokens = _tokens(right_normal)
    union = left_tokens | right_tokens
    jaccard = len(left_tokens & right_tokens) / len(union) if union else 0.0
    ratio = SequenceMatcher(None, left_normal, right_normal, autojunk=False).ratio()
    return jaccard >= 0.85 or ratio >= 0.92


def _operation(actions: Iterable[str]) -> tuple[str, bool]:
    action_set = set(actions)
    if "delete" in action_set and "create" in action_set:
        return "replace", True
    if "delete" in action_set:
        return "delete", True
    if "create" in action_set:
        return "create", False
    if "update" in action_set:
        return "update", False
    return "no-op", False


def normalize_operations(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    for index, change in enumerate(plan.get("resource_changes", [])):
        if not isinstance(change, dict):
            raise CompilationError("resource change must be an object")
        detail = change.get("change") or {}
        if not isinstance(detail, Mapping):
            raise CompilationError("resource change detail must be an object")
        actions = detail.get("actions") or []
        if not isinstance(actions, list) or not all(isinstance(action, str) for action in actions):
            raise CompilationError("resource actions must be strings")
        effect, destructive = _operation(actions)
        before = detail.get("before") if isinstance(detail.get("before"), dict) else {}
        after = detail.get("after") if isinstance(detail.get("after"), dict) else {}
        identity = before or after
        address = str(change.get("address", ""))
        name = str(identity.get("name") or address.rsplit(".", 1)[-1])
        operations.append(
            {
                "operation_id": f"operation-{index + 1}",
                "address": address,
                "resource_type": str(change.get("type", "")),
                "provider": str(change.get("provider_name", "")),
                "actions": actions,
                "effect": effect,
                "destructive": destructive,
                "name": name,
                "project": identity.get("project"),
                "environment": identity.get("environment"),
                "generation": identity.get("generation"),
            }
        )
    return operations


def _resource_matches(
    operation: Mapping[str, Any],
    candidate: Any,
    aliases: Iterable[Any] = (),
    *,
    strong: bool = True,
) -> bool:
    if not isinstance(candidate, str) or not candidate:
        return False
    choices = {str(operation.get("address", "")), str(operation.get("name", ""))}
    choices.update(str(alias) for alias in aliases)
    if strong:
        return any(_similar(candidate, choice) for choice in choices if choice)
    return candidate in choices


def _aliases(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item)


def _new_blocker(code: str, message: str, evidence_refs: Iterable[str]) -> dict[str, Any]:
    refs = sorted(set(str(ref) for ref in evidence_refs if ref))
    digest = hashlib.sha256((code + "\0" + "\0".join(refs)).encode("utf-8")).hexdigest()[:12]
    return {
        "blocker_id": f"blocker-{digest}",
        "code": code,
        "message": message,
        "evidence_refs": refs,
        "decision_effect": "block",
    }


def _append_unique(rows: list[dict[str, Any]], row: dict[str, Any], key: str) -> None:
    if not any(existing.get(key) == row.get(key) for existing in rows):
        rows.append(row)


def _structured_checks(
    packet: dict[str, Any],
    case: Mapping[str, Any],
    artifacts: Mapping[str, Any],
    operations: list[dict[str, Any]],
    *,
    strong: bool,
) -> None:
    manifest = _first_mapping(_values_by_kind(case, artifacts, "service_manifest"))
    ownership = _first_mapping(_values_by_kind(case, artifacts, "ownership"))
    ledger = _first_mapping(_values_by_kind(case, artifacts, "recovery_ledger"))
    ticket = _first_mapping(_values_by_kind(case, artifacts, "change_ticket"))
    policy = case.get("policy") if isinstance(case.get("policy"), dict) else {}
    plan_ref = _first_artifact_id(case, "terraform_plan")
    manifest_ref = _first_artifact_id(case, "service_manifest")
    ownership_ref = _first_artifact_id(case, "ownership")
    ledger_ref = _first_artifact_id(case, "recovery_ledger")
    ticket_ref = _first_artifact_id(case, "change_ticket")
    reference_time = _parse_time(policy.get("reference_time"))
    max_age = policy.get("max_evidence_age_seconds")

    for operation in operations:
        packet["facts"].append(
            {
                "fact_id": operation["operation_id"],
                "kind": "normalized_operation",
                "value": operation,
                "source": plan_ref,
            }
        )
        if not operation["destructive"]:
            continue
        packet["derivations"].append(
            {
                "derivation_id": f"{operation['operation_id']}-destructive",
                "kind": "destructive_operation_classification",
                "value": {"effect": operation["effect"], "destructive": True},
                "evidence_refs": [operation["operation_id"]],
            }
        )

        missing_scope = [
            key
            for key in ("project", "environment", "generation")
            if not isinstance(operation.get(key), str) or not operation[key]
        ]
        if missing_scope:
            packet["unknowns"].append(
                {
                    "code": "DESTRUCTIVE_TARGET_SCOPE_INCOMPLETE",
                    "operation_id": operation["operation_id"],
                }
            )
            _append_unique(
                packet["blockers"],
                _new_blocker(
                    "REQUIRED_EVIDENCE_UNKNOWN",
                    "The destructive target lacks complete project, environment, or generation scope.",
                    [operation["operation_id"], plan_ref],
                ),
                "blocker_id",
            )

        intended_environment = ticket.get("intended_environment")
        if intended_environment and operation.get("environment") and intended_environment != operation["environment"]:
            _append_unique(
                packet["blockers"],
                _new_blocker(
                    "DESTRUCTIVE_INTENT_MISMATCH",
                    "The structured target environment differs from the stated environment.",
                    [operation["operation_id"], ticket_ref],
                ),
                "blocker_id",
            )
        intended_effect = ticket.get("intended_effect")
        if intended_effect in {"resize", "update"} and operation["effect"] in {"delete", "replace"}:
            _append_unique(
                packet["blockers"],
                _new_blocker(
                    "DESTRUCTIVE_INTENT_MISMATCH",
                    "The structured intended effect does not include destructive replacement.",
                    [operation["operation_id"], ticket_ref],
                ),
                "blocker_id",
            )
        owner_rows = ownership.get("resources", []) if isinstance(ownership.get("resources"), list) else []
        exact_owners = [
            row
            for row in owner_rows
            if isinstance(row, dict)
            and _resource_matches(
                operation,
                row.get("resource_ref"),
                _aliases(row.get("aliases")),
                strong=strong,
            )
            and _scope_equal(row, operation)
        ]
        resource_owners = [
            row
            for row in owner_rows
            if isinstance(row, dict)
            and _resource_matches(
                operation,
                row.get("resource_ref"),
                _aliases(row.get("aliases")),
                strong=strong,
            )
        ]
        if resource_owners and not exact_owners:
            _append_unique(
                packet["blockers"],
                _new_blocker(
                    "RESOURCE_GENERATION_MISMATCH",
                    "Ownership evidence refers to another environment or resource generation.",
                    [operation["operation_id"], ownership_ref],
                ),
                "blocker_id",
            )
        owner_pairs = {
            (str(row.get("owner")), str(row.get("recovery_owner")))
            for row in exact_owners
            if row.get("owner") or row.get("recovery_owner")
        }
        if len(owner_pairs) > 1:
            _append_unique(
                packet["blockers"],
                _new_blocker(
                    "OWNER_CONFLICT",
                    "Structured ownership records conflict for the same resource generation.",
                    [operation["operation_id"], ownership_ref],
                ),
                "blocker_id",
            )
        required_owner_fields = policy.get("required_owner_fields", [])
        owner_complete = any(
            all(
                row.get(field)
                for field in required_owner_fields
                if isinstance(field, str)
            )
            for row in exact_owners
        )
        if not owner_complete:
            packet["unknowns"].append(
                {
                    "code": "OWNER_EVIDENCE_INCOMPLETE",
                    "operation_id": operation["operation_id"],
                }
            )
            _append_unique(
                packet["blockers"],
                _new_blocker(
                    "REQUIRED_EVIDENCE_UNKNOWN",
                    "Required ownership evidence is missing or scoped to another resource generation.",
                    [operation["operation_id"], ownership_ref],
                ),
                "blocker_id",
            )

        dependencies: list[tuple[str, dict[str, Any]]] = []
        for service in manifest.get("services", []) if isinstance(manifest.get("services"), list) else []:
            if not isinstance(service, dict):
                continue
            for dependency in service.get("dependencies", []) if isinstance(service.get("dependencies"), list) else []:
                if not isinstance(dependency, dict) or dependency.get("active") is False:
                    continue
                if _resource_matches(
                    operation,
                    dependency.get("resource_ref"),
                    _aliases(dependency.get("aliases")),
                    strong=strong,
                ) and _scope_equal(dependency, operation):
                    dependencies.append((str(service.get("service_id", "service")), dependency))

        for service_id, dependency in dependencies:
            records = ledger.get("records", []) if isinstance(ledger.get("records"), list) else []
            dependency_aliases = _aliases(dependency.get("aliases"))
            resource_records = [
                record
                for record in records
                if isinstance(record, dict)
                and _resource_matches(
                    operation,
                    record.get("resource_ref"),
                    (*dependency_aliases, *_aliases(record.get("aliases"))),
                    strong=strong,
                )
            ]
            matches = [
                record
                for record in resource_records
                if _scope_equal(record, operation)
            ]
            if not matches:
                if resource_records:
                    _append_unique(
                        packet["blockers"],
                        _new_blocker(
                            "RECOVERY_SCOPE_MISMATCH",
                            "Recovery evidence is scoped to another environment or resource generation.",
                            [operation["operation_id"], manifest_ref, ledger_ref],
                        ),
                        "blocker_id",
                    )
                _append_unique(
                    packet["blockers"],
                    _new_blocker(
                        "DEPENDENCY_RECOVERY_EVIDENCE_MISSING",
                        "An exact dependent service lacks recovery evidence for this resource generation.",
                        [operation["operation_id"], manifest_ref, ledger_ref],
                    ),
                    "blocker_id",
                )
                continue
            valid_records = 0
            fresh_records = 0
            stale_records = 0
            invalid_timestamps = 0
            passing_canaries = 0
            for record_index, record in enumerate(matches):
                tested_at = _parse_time(record.get("tested_at"))
                age: float | None = None
                if reference_time is not None:
                    if tested_at is None:
                        invalid_timestamps += 1
                    else:
                        age = (reference_time - tested_at).total_seconds()
                        if age < 0:
                            invalid_timestamps += 1
                        elif isinstance(max_age, (int, float)) and age > max_age:
                            stale_records += 1
                if age is not None:
                    packet["derivations"].append(
                        {
                            "derivation_id": (
                                f"{operation['operation_id']}-{service_id}-"
                                f"evidence-age-{record_index + 1}"
                            ),
                            "kind": "recovery_evidence_age",
                            "value": {
                                "service_id": service_id,
                                "age_seconds": age,
                                "limit_seconds": max_age,
                            },
                            "evidence_refs": [
                                operation["operation_id"],
                                manifest_ref,
                                ledger_ref,
                            ],
                        }
                    )
                if record.get("application_canary") is True:
                    passing_canaries += 1
                fresh = (
                    reference_time is None
                    or (
                        tested_at is not None
                        and age is not None
                        and age >= 0
                        and (
                            not isinstance(max_age, (int, float))
                            or age <= max_age
                        )
                    )
                )
                if fresh and record.get("application_canary") is True:
                    valid_records += 1
                if fresh:
                    fresh_records += 1

            if valid_records:
                continue
            if invalid_timestamps:
                packet["unknowns"].append(
                    {
                        "code": "RECOVERY_TIMESTAMP_INVALID",
                        "operation_id": operation["operation_id"],
                    }
                )
                _append_unique(
                    packet["blockers"],
                    _new_blocker(
                        "REQUIRED_EVIDENCE_UNKNOWN",
                        "The recovery evidence timestamp is missing, invalid, or in the future.",
                        [operation["operation_id"], manifest_ref, ledger_ref],
                    ),
                    "blocker_id",
                )
            if stale_records:
                _append_unique(
                    packet["blockers"],
                    _new_blocker(
                        "RECOVERY_EVIDENCE_STALE",
                        "Application recovery evidence exceeds the configured age limit.",
                        [operation["operation_id"], manifest_ref, ledger_ref],
                    ),
                    "blocker_id",
                )
            if fresh_records or not passing_canaries:
                _append_unique(
                    packet["blockers"],
                    _new_blocker(
                        "DEPENDENCY_RECOVERY_EVIDENCE_MISSING",
                        "The scoped recovery record does not contain a passing application canary.",
                        [operation["operation_id"], manifest_ref, ledger_ref],
                    ),
                    "blocker_id",
                )


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _scope_equal(row: Mapping[str, Any], operation: Mapping[str, Any]) -> bool:
    for key in ("project", "environment", "generation"):
        operation_value = operation.get(key)
        row_value = row.get(key)
        if (
            not isinstance(operation_value, str)
            or not operation_value
            or not isinstance(row_value, str)
            or not row_value
        ):
            return False
        if row_value != operation_value:
            return False
    return True


def _text_corpus(
    case: Mapping[str, Any], artifacts: Mapping[str, Any]
) -> tuple[str, tuple[str, ...]]:
    parts: list[str] = []
    refs: list[str] = []
    for entry in case.get("artifacts", []):
        value = artifacts[entry["artifact_id"]]["value"]
        if isinstance(value, str) and entry.get("kind") in {
            "pr_description",
            "change_ticket_text",
            "runbook",
        }:
            parts.append(value)
            refs.append(entry["artifact_id"])
    return "\n".join(parts), tuple(refs)


def _generic_rule_checks(
    packet: dict[str, Any],
    operations: list[dict[str, Any]],
    corpus: str,
    corpus_refs: tuple[str, ...],
) -> None:
    normalized = _normal_form(corpus)
    tokens = set(normalized.split())
    for operation in operations:
        if not operation["destructive"]:
            continue
        environment = _normal_form(operation.get("environment") or "")
        if environment == "production" and "staging" in tokens and "production" not in tokens:
            _append_unique(
                packet["blockers"],
                _new_blocker(
                    "DESTRUCTIVE_INTENT_MISMATCH",
                    "Textual change intent names staging while the structured target is production.",
                    [operation["operation_id"], *corpus_refs],
                ),
                "blocker_id",
            )
        resize_terms = {"resize", "expand", "increase", "scale"}
        if operation["effect"] in {"delete", "replace"} and resize_terms & tokens:
            _append_unique(
                packet["blockers"],
                _new_blocker(
                    "DESTRUCTIVE_INTENT_MISMATCH",
                    "Textual intent describes a non-destructive capacity change.",
                    [operation["operation_id"], *corpus_refs],
                ),
                "blocker_id",
            )
        if "retired" in tokens or "decommissioned" in tokens or "migrated" in tokens:
            packet["advisory"].append(
                {
                    "advisory_id": f"{operation['operation_id']}-retirement-language",
                    "kind": "retirement_language_present",
                    "value": {"operation_id": operation["operation_id"]},
                    "evidence_refs": [operation["operation_id"], *corpus_refs],
                }
            )


def compile_case(
    case_dir: Path,
    arm: str,
    *,
    semantic: Mapping[str, Any] | None = None,
    include_recovery: bool = True,
    allow_heldout: bool = False,
) -> dict[str, Any]:
    if arm not in ARMS:
        raise CompilationError(f"unknown arm: {arm}")
    case, artifacts = load_case(Path(case_dir))
    if case["split"] == "heldout" and not allow_heldout:
        raise CompilationError("heldout compilation requires the locked evaluator")
    plan = _first_mapping(_values_by_kind(case, artifacts, "terraform_plan"))
    if not plan:
        raise CompilationError("case has no Terraform plan")
    operations = normalize_operations(plan)
    packet: dict[str, Any] = {
        "schema_version": "lazarus.evidence-packet/v1",
        "case_id": case.get("case_id"),
        "arm": arm,
        "facts": [],
        "derivations": [],
        "semantic": {"admitted": [], "rejected": [], "abstained": False, "requested_evidence": []},
        "advisory": [],
        "unknowns": [],
        "blockers": [],
        "recovery": _unknown_recovery(),
        "human_decision_state": SAFE_HUMAN_STATE,
        "semantic_status": "not_requested",
    }
    _structured_checks(
        packet,
        case,
        artifacts,
        operations,
        strong=arm != "a0",
    )
    if arm == "a1-rules":
        corpus, corpus_refs = _text_corpus(case, artifacts)
        _generic_rule_checks(packet, operations, corpus, corpus_refs)
    if arm in B_ARMS:
        _apply_semantic(
            packet,
            case,
            semantic,
            artifacts,
            operations,
            disabled_relation_types=B_ARM_DISABLED_RELATIONS[arm],
        )
    if include_recovery and case.get("recovery"):
        from lazarus.recovery import run_recovery

        packet["recovery"] = run_recovery(Path(case_dir), case["recovery"])
    _apply_recovery_blockers(packet)
    if packet["blockers"]:
        if all(blocker["code"] == "SEMANTIC_CONFIRMATION_REQUIRED" for blocker in packet["blockers"]):
            packet["human_decision_state"] = "needs_confirmation"
        else:
            packet["human_decision_state"] = "blocked"
    elif any(
        proposal.get("evidence_class") == "candidate_inference"
        for proposal in packet["semantic"]["admitted"]
    ):
        packet["human_decision_state"] = "needs_confirmation"
    from lazarus.protocol import validate_evidence_packet

    artifact_texts = {artifact_id: artifact["raw"] for artifact_id, artifact in artifacts.items()}
    return validate_evidence_packet(packet, case=case, artifact_texts=artifact_texts)


def _apply_semantic(
    packet: dict[str, Any],
    case: Mapping[str, Any],
    semantic: Mapping[str, Any] | None,
    artifacts: Mapping[str, Any],
    operations: list[dict[str, Any]],
    *,
    disabled_relation_types: frozenset[str],
) -> None:
    if semantic is None:
        from lazarus.resolver import unavailable_semantic_resolution

        packet["semantic"] = unavailable_semantic_resolution(["cited semantic evidence"])
        packet["semantic_status"] = "unavailable"
        return
    from lazarus.resolver import resolve_semantic_output

    artifact_texts = {artifact_id: artifact["raw"] for artifact_id, artifact in artifacts.items()}
    disabled_artifact_ids = frozenset(
        entry["artifact_id"]
        for entry in case.get("artifacts", [])
        if isinstance(entry, Mapping)
        and entry.get("kind") == "incident"
        and "incident_relevance_advisory" in disabled_relation_types
    )
    resolution = resolve_semantic_output(
        case,
        semantic,
        artifact_texts,
        disabled_relation_types=disabled_relation_types,
        disabled_artifact_ids=disabled_artifact_ids,
    )
    packet["semantic"] = resolution
    packet["semantic_status"] = "available"
    abstained = resolution.get("abstained") is True
    if abstained:
        packet["unknowns"].append({"code": "SEMANTIC_EVIDENCE_INCOMPLETE"})
    consequence_blocked = False
    for proposal in resolution.get("admitted", []):
        relation_type = proposal.get("relation_type")
        consequence_refs: list[str] = []
        if relation_type == "intent_effect_contradiction":
            consequence_refs = _intent_consequence_refs(
                proposal,
                case,
                operations,
            )
        elif relation_type in {
            "resource_alias_candidate",
            "conditional_dependency_candidate",
        }:
            consequence_refs = _dependency_consequence_refs(
                proposal,
                case,
                artifacts,
                operations,
            )
        if consequence_refs:
            proposal_id = str(proposal.get("proposal_id", "semantic-proposal"))
            blocker_refs = [proposal_id, *consequence_refs]
            if abstained:
                blocker_refs.append("semantic:abstention")
            consequence_id = hashlib.sha256(
                (proposal_id + "\0" + "\0".join(consequence_refs)).encode("utf-8")
            ).hexdigest()[:12]
            packet["derivations"].append(
                {
                    "derivation_id": f"semantic-consequence-{consequence_id}",
                    "kind": "semantic_candidate_consequence",
                    "value": {
                        "proposal_id": proposal_id,
                        "relation_type": relation_type,
                        "requires_human_confirmation": True,
                    },
                    "evidence_refs": [proposal_id, *consequence_refs],
                }
            )
            _append_unique(
                packet["blockers"],
                _new_blocker(
                    "SEMANTIC_CONFIRMATION_REQUIRED",
                    "A cited semantic candidate has a deterministic change consequence and requires human confirmation.",
                    blocker_refs,
                ),
                "blocker_id",
            )
            consequence_blocked = True
        elif relation_type == "incident_relevance_advisory":
            proposal_id = str(proposal.get("proposal_id", "semantic-proposal"))
            packet["advisory"].append(
                {
                    "advisory_id": f"{proposal_id}-incident-context",
                    "kind": "incident_context_candidate",
                    "value": {"proposal_id": proposal_id},
                    "evidence_refs": [proposal_id],
                }
            )
    if abstained and not consequence_blocked:
        _append_unique(
            packet["blockers"],
            _new_blocker(
                "SEMANTIC_CONFIRMATION_REQUIRED",
                "The semantic resolver abstained and requested additional evidence.",
                ["semantic:abstention"],
            ),
            "blocker_id",
        )


def _intent_consequence_refs(
    proposal: Mapping[str, Any],
    case: Mapping[str, Any],
    operations: list[dict[str, Any]],
) -> list[str]:
    from lazarus.resolver import citation_supports_endpoint, relation_endpoints_are_distinct

    if not relation_endpoints_are_distinct(proposal):
        return []
    declared_context_ids = {
        entry["artifact_id"]
        for entry in case.get("artifacts", [])
        if isinstance(entry, Mapping) and entry.get("authority") == "declared_context"
    }
    structured_ids = {
        entry["artifact_id"]
        for entry in case.get("artifacts", [])
        if isinstance(entry, Mapping)
        and entry.get("authority") == "structured_fact"
    }
    citations = [
        citation
        for citation in proposal.get("citations", [])
        if isinstance(citation, Mapping)
    ]
    endpoints = (proposal.get("subject"), proposal.get("object"))
    supported_ids = tuple(
        {
            citation.get("artifact_id")
            for citation in citations
            if citation_supports_endpoint(citation, endpoint)
        }
        for endpoint in endpoints
    )
    if not any(ids.intersection(declared_context_ids) for ids in supported_ids):
        return []
    consequences: list[str] = []
    for operation in operations:
        if operation.get("destructive") is not True:
            continue
        operation_endpoints = {
            index
            for index, endpoint in enumerate(endpoints)
            if _resource_matches(operation, endpoint, strong=True)
            or _similar(endpoint, operation.get("effect"))
            or any(
                _similar(endpoint, action)
                for action in operation.get("actions", [])
            )
        }
        if any(
            supported_ids[index].intersection(structured_ids)
            and supported_ids[1 - index].intersection(declared_context_ids)
            for index in operation_endpoints
        ):
            consequences.append(operation["operation_id"])
    return consequences


def _dependency_consequence_refs(
    proposal: Mapping[str, Any],
    case: Mapping[str, Any],
    artifacts: Mapping[str, Any],
    operations: list[dict[str, Any]],
) -> list[str]:
    subject = proposal.get("subject")
    object_ = proposal.get("object")
    if not isinstance(subject, str) or not isinstance(object_, str):
        return []
    manifest = _first_mapping(_values_by_kind(case, artifacts, "service_manifest"))
    relation_type = proposal.get("relation_type")
    for operation in operations:
        if operation.get("destructive") is not True:
            continue
        for operation_endpoint, other_endpoint in ((subject, object_), (object_, subject)):
            if not _resource_matches(operation, operation_endpoint, strong=True):
                continue
            services = manifest.get("services", [])
            for service in services if isinstance(services, list) else []:
                if not isinstance(service, Mapping):
                    continue
                service_id = str(service.get("service_id", "service"))
                service_names = (service_id, *_aliases(service.get("aliases")))
                dependencies = service.get("dependencies", [])
                for dependency in dependencies if isinstance(dependencies, list) else []:
                    if not isinstance(dependency, Mapping) or dependency.get("active") is False:
                        continue
                    dependency_names = (
                        str(dependency.get("resource_ref", "")),
                        *_aliases(dependency.get("aliases")),
                    )
                    endpoint_matches_dependency = any(
                        _similar(other_endpoint, name)
                        for name in dependency_names
                        if name
                    )
                    endpoint_matches_service = any(
                        _similar(other_endpoint, name)
                        for name in service_names
                        if name
                    )
                    if relation_type == "resource_alias_candidate":
                        consequential = endpoint_matches_dependency
                    else:
                        consequential = endpoint_matches_dependency or endpoint_matches_service
                    if consequential and _scope_equal(dependency, operation):
                        return [
                            operation["operation_id"],
                            _first_artifact_id(case, "service_manifest"),
                        ]
    return []


def _unknown_recovery() -> dict[str, Any]:
    return {
        "restore": {"status": "unknown", "elapsed_ms": None},
        "canary": {
            "status": "unknown",
            "checks": [
                {"check_id": "integrity", "check_type": "integrity", "status": "unknown"},
                {"check_id": "schema", "check_type": "schema", "status": "unknown"},
                {
                    "check_id": "required_queries",
                    "check_type": "required_query",
                    "status": "unknown",
                },
                {
                    "check_id": "business_invariants",
                    "check_type": "business_invariant",
                    "status": "unknown",
                },
            ],
        },
        "rpo": {"status": "unknown", "age_seconds": None, "objective_seconds": 0},
        "rto": {"status": "unknown", "elapsed_ms": None, "objective_ms": 0},
        "cleanup": {"status": "unknown"},
        "classification": "unknown",
        "timing": {
            "clock": "unavailable",
            "rto_started_ns": None,
            "restore_started_ns": None,
            "restore_completed_ns": None,
            "rto_completed_ns": None,
        },
    }


def _apply_recovery_blockers(packet: dict[str, Any]) -> None:
    recovery = packet["recovery"]
    mapping = {
        ("restore", "fail"): ("RESTORE_FAILED", "The disposable restore did not complete."),
        ("canary", "fail"): ("CANARY_FAILED", "The deterministic application canary failed."),
        ("rpo", "fail"): ("RPO_BREACH", "The recovery point objective was not met."),
        ("rto", "fail"): ("RTO_BREACH", "The recovery time objective was not met."),
        ("cleanup", "fail"): ("CLEANUP_FAILED", "Disposable recovery cleanup failed."),
    }
    for (section, status), (code, message) in mapping.items():
        result = recovery.get(section, {})
        if isinstance(result, dict) and result.get("status") == status:
            _append_unique(packet["blockers"], _new_blocker(code, message, [f"recovery:{section}"]), "blocker_id")
    for section in ("restore", "canary", "rpo", "rto", "cleanup"):
        result = recovery.get(section, {})
        if isinstance(result, dict) and result.get("status") == "unknown":
            packet["unknowns"].append(
                {"code": f"RECOVERY_{section.upper()}_UNKNOWN"}
            )
            _append_unique(
                packet["blockers"],
                _new_blocker(
                    "REQUIRED_EVIDENCE_UNKNOWN",
                    f"The deterministic recovery {section} result is unavailable or incomplete.",
                    [f"recovery:{section}"],
                ),
                "blocker_id",
            )
