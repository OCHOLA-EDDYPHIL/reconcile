from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from lazarus.locking import (
    LockVerificationError,
    LockingError,
    build_lock_manifest,
    canonical_json_bytes,
    canonical_sha256,
    validate_model_settings,
    verify_lock_manifest,
    write_lock_manifest,
)
from lazarus.protocol import (
    RELATION_TYPES,
    ProtocolValidationError,
    validate_case_contract,
    validate_evidence_packet,
    validate_recovery_result,
)
from lazarus.recovery import (
    RecoveryMatrixError,
    load_recovery_matrix_inputs,
)


CASE_SCHEMA_VERSION = "lazarus.case/v1"
ORACLE_SCHEMA_VERSION = "lazarus.oracle/v1"
RAW_RESULT_SCHEMA_VERSION = "lazarus.raw-result/v1"
RAW_ENVELOPE_SCHEMA_VERSION = "lazarus.raw-result-envelope/v1"
MODEL_CAPTURE_SCHEMA_VERSION = "lazarus.model-capture/v1"
SCORE_SCHEMA_VERSION = "lazarus.benchmark-score/v1"
SPLITS = ("calibration", "heldout")
AUTHORITIES = ("structured_fact", "declared_context", "advisory_context")
RECOVERY_EXPECTATION_FIELDS = ("restore", "canary", "rpo", "rto", "cleanup")
RECOVERY_STATUSES = frozenset({"pass", "fail", "unknown"})
HELDOUT_COVERAGE = frozenset(
    {
        "direct_destructive_target",
        "exact_dependency",
        "semantic_alias",
        "generation_mismatch",
        "stale_recovery",
        "canary_invariant",
        "rto_breach",
        "nuanced_intent",
        "similar_names",
        "retired_dependency",
        "fresh_proof",
        "embedded_hostile_instruction",
    }
)
RECOVERY_REPEATABILITY_STATES = (
    "fresh",
    "schema",
    "invariant",
    "stale",
    "rto",
    "cleanup",
)
ABLATION_ARMS = (
    "b-replay-no-alias",
    "b-replay-no-intent",
    "b-replay-no-probe",
    "b-replay-no-incident",
)
MODEL_ARMS = ("b-replay", *ABLATION_ARMS)
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_RESERVED_ORACLE_KEYS = frozenset(
    {
        "abstention_required",
        "acceptable_matches",
        "coverage",
        "decision_changing_blockers",
        "negative_control",
        "oracle_id",
        "recovery_expectation",
        "required_probe",
    }
)


class BenchmarkError(ValueError):
    pass


@dataclass(frozen=True)
class BenchmarkCase:
    directory: Path
    definition: dict[str, Any]
    artifacts: dict[str, Path]

    @property
    def case_id(self) -> str:
        return self.definition["case_id"]

    @property
    def split(self) -> str:
        return self.definition["split"]

    @property
    def oracle_path(self) -> Path:
        return self.directory / "oracle" / "oracle.json"


def discover_cases(fixtures_root: str | os.PathLike[str], split: str | None = None) -> tuple[Path, ...]:
    root = Path(fixtures_root)
    if split is not None and split not in SPLITS:
        raise BenchmarkError(f"unknown split: {split}")
    selected = (split,) if split else SPLITS
    paths: list[Path] = []
    for name in selected:
        split_root = root / name
        if not split_root.is_dir():
            continue
        paths.extend(sorted(path.parent for path in split_root.glob("*/case.json") if path.is_file()))
    return tuple(paths)


def load_case(case_path: str | os.PathLike[str]) -> BenchmarkCase:
    supplied = Path(case_path)
    case_file = supplied if supplied.name == "case.json" else supplied / "case.json"
    directory = case_file.parent.resolve()
    definition = _load_json_object(case_file, "case")
    try:
        validate_case_contract(definition)
    except ProtocolValidationError as exc:
        raise BenchmarkError(str(exc)) from exc
    if definition.get("schema_version") != CASE_SCHEMA_VERSION:
        raise BenchmarkError("unsupported case schema")
    case_id = definition.get("case_id")
    if not isinstance(case_id, str) or not _SAFE_IDENTIFIER.fullmatch(case_id):
        raise BenchmarkError("case_id must be a safe non-empty identifier")
    if definition.get("split") not in SPLITS:
        raise BenchmarkError("case split must be calibration or heldout")
    if not isinstance(definition.get("recovery"), dict):
        raise BenchmarkError("case recovery must be an object")
    if not isinstance(definition.get("policy"), dict):
        raise BenchmarkError("case policy must be an object")

    entries = definition.get("artifacts")
    if not isinstance(entries, list) or not entries:
        raise BenchmarkError("case artifacts must be a non-empty list")
    artifacts: dict[str, Path] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise BenchmarkError("artifact entries must be objects")
        artifact_id = entry.get("artifact_id")
        kind = entry.get("kind")
        relative = entry.get("path")
        authority = entry.get("authority")
        if not isinstance(artifact_id, str) or not _SAFE_IDENTIFIER.fullmatch(artifact_id):
            raise BenchmarkError("artifact_id must be a safe non-empty identifier")
        if artifact_id in artifacts:
            raise BenchmarkError(f"duplicate artifact_id: {artifact_id}")
        if not isinstance(kind, str) or not _SAFE_IDENTIFIER.fullmatch(kind):
            raise BenchmarkError(f"artifact {artifact_id} has an invalid kind")
        if authority not in AUTHORITIES:
            raise BenchmarkError(f"artifact {artifact_id} has an invalid authority")
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            raise BenchmarkError(f"artifact {artifact_id} has an invalid path")
        if "oracle" in {part.casefold() for part in Path(relative).parts}:
            raise BenchmarkError("oracle files cannot be model-input artifacts")
        resolved = (directory / relative).resolve()
        try:
            resolved.relative_to(directory)
        except ValueError as exc:
            raise BenchmarkError(f"artifact {artifact_id} escapes its case directory") from exc
        if not resolved.is_file():
            raise BenchmarkError(f"artifact {artifact_id} does not exist")
        if resolved.suffix.casefold() == ".json":
            try:
                artifact_value = json.loads(
                    resolved.read_text(encoding="utf-8"),
                    object_pairs_hook=_unique_json_mapping,
                )
            except (OSError, UnicodeError, ValueError) as exc:
                raise BenchmarkError(f"cannot load artifact {artifact_id}: {exc}") from exc
            leaked = _reserved_oracle_keys(artifact_value)
            if leaked:
                raise BenchmarkError(
                    f"artifact {artifact_id} contains reserved oracle fields: {sorted(leaked)}"
                )
        artifacts[artifact_id] = resolved

    oracle_path = directory / "oracle" / "oracle.json"
    if not oracle_path.is_file():
        raise BenchmarkError(f"case {case_id} has no separate oracle")
    return BenchmarkCase(directory, definition, artifacts)


def load_oracle(case_path: str | os.PathLike[str]) -> dict[str, Any]:
    case = load_case(case_path)
    oracle = _load_json_object(case.oracle_path, "oracle")
    if oracle.get("schema_version") != ORACLE_SCHEMA_VERSION:
        raise BenchmarkError("unsupported oracle schema")
    if oracle.get("case_id") != case.case_id:
        raise BenchmarkError("oracle case_id does not match the case")
    allowed_fields = {
        "schema_version",
        "case_id",
        "negative_control",
        "decision_changing_blockers",
        "advisory_findings",
        "coverage",
        "abstention_required",
        "required_probe",
        "recovery_expectation",
    }
    if set(oracle) != allowed_fields:
        raise BenchmarkError("oracle fields do not match the protocol")
    negative = oracle.get("negative_control")
    if not isinstance(negative, bool):
        raise BenchmarkError("oracle negative_control must be boolean")
    blockers = oracle.get("decision_changing_blockers")
    if not isinstance(blockers, list):
        raise BenchmarkError("oracle decision_changing_blockers must be a list")
    if negative and blockers:
        raise BenchmarkError("a negative control cannot contain a decision-changing blocker")
    if not negative and not blockers:
        raise BenchmarkError("a blocker case must contain a decision-changing blocker")
    oracle_ids: set[str] = set()
    for blocker in blockers:
        _validate_oracle_blocker(blocker)
        if blocker["oracle_id"] in oracle_ids:
            raise BenchmarkError("oracle blocker identifiers must be unique")
        oracle_ids.add(blocker["oracle_id"])
    advisory = oracle.get("advisory_findings", [])
    if not isinstance(advisory, list):
        raise BenchmarkError("oracle advisory_findings must be a list")
    coverage = oracle.get("coverage")
    if not isinstance(coverage, list) or not coverage or not all(isinstance(item, str) for item in coverage):
        raise BenchmarkError("oracle coverage must be a non-empty string list")
    if not isinstance(oracle.get("abstention_required", False), bool):
        raise BenchmarkError("oracle abstention_required must be boolean")
    probe = oracle.get("required_probe")
    if probe is not None and (not isinstance(probe, str) or not probe):
        raise BenchmarkError("oracle required_probe must be null or a non-empty string")
    _validate_recovery_expectation(oracle.get("recovery_expectation"))
    return oracle


def _validate_recovery_expectation(expectation: Any) -> None:
    if not isinstance(expectation, Mapping) or set(expectation) != set(
        RECOVERY_EXPECTATION_FIELDS
    ):
        raise BenchmarkError("oracle recovery_expectation must define all five sections")
    if any(expectation[field] not in RECOVERY_STATUSES for field in RECOVERY_EXPECTATION_FIELDS):
        raise BenchmarkError("oracle recovery expectation has an invalid status")
    if (
        expectation["restore"] != "pass"
        or expectation["canary"] != "pass"
    ) and expectation["rto"] != "unknown":
        raise BenchmarkError(
            "oracle RTO must be unknown when restore or canary does not pass"
        )


def validate_suite(fixtures_root: str | os.PathLike[str]) -> dict[str, int]:
    cases = [load_case(path) for path in discover_cases(fixtures_root)]
    for case in cases:
        if case.directory.parent.name != case.split:
            raise BenchmarkError(f"case {case.case_id} is stored under the wrong split")
    counts = {split: sum(case.split == split for case in cases) for split in SPLITS}
    if counts != {"calibration": 4, "heldout": 12}:
        raise BenchmarkError("the suite must contain four calibration and twelve heldout cases")
    if len({case.case_id for case in cases}) != len(cases):
        raise BenchmarkError("case identifiers must be unique across the suite")

    heldout_oracles = [load_oracle(case.directory) for case in cases if case.split == "heldout"]
    negative_count = sum(oracle["negative_control"] for oracle in heldout_oracles)
    blocker_count = len(heldout_oracles) - negative_count
    if (blocker_count, negative_count) != (8, 4):
        raise BenchmarkError("heldout cases must contain eight blockers and four negative controls")
    if any(len(oracle["coverage"]) != 1 for oracle in heldout_oracles):
        raise BenchmarkError("each heldout case must cover exactly one required scenario")
    coverage_counts = Counter(oracle["coverage"][0] for oracle in heldout_oracles)
    heldout_coverage = set(coverage_counts)
    if heldout_coverage != HELDOUT_COVERAGE:
        missing = sorted(HELDOUT_COVERAGE - heldout_coverage)
        extra = sorted(heldout_coverage - HELDOUT_COVERAGE)
        raise BenchmarkError(f"heldout coverage mismatch; missing={missing}, extra={extra}")
    if any(count != 1 for count in coverage_counts.values()):
        raise BenchmarkError("heldout scenario coverage must be one-to-one")
    return {
        "calibration": counts["calibration"],
        "heldout": counts["heldout"],
        "heldout_blockers": blocker_count,
        "heldout_negative_controls": negative_count,
    }


def freeze_benchmark(
    fixtures_root: str | os.PathLike[str],
    *,
    model_settings: Mapping[str, Any],
    destination: str | os.PathLike[str] | None = None,
    repository_root: str | os.PathLike[str] | None = None,
    evaluator_paths: Iterable[str | os.PathLike[str]] | None = None,
) -> dict[str, Any]:
    fixture_base = Path(fixtures_root).resolve()
    validate_suite(fixture_base)
    repository = Path(repository_root).resolve() if repository_root else fixture_base.parent.resolve()
    case_files, oracle_files, schemas, prompts = _benchmark_lock_inputs(
        fixture_base, repository
    )
    if evaluator_paths is None:
        evaluator_paths = _default_evaluator_paths(repository)
    manifest = build_lock_manifest(
        repository,
        fixtures=case_files,
        oracles=oracle_files,
        schemas=schemas,
        prompts=prompts,
        evaluator=evaluator_paths,
        model_settings=model_settings,
    )
    if destination is not None:
        write_lock_manifest(destination, manifest)
    return manifest


def verify_benchmark_lock(
    manifest: Mapping[str, Any] | str | os.PathLike[str],
    fixtures_root: str | os.PathLike[str],
    *,
    repository_root: str | os.PathLike[str] | None = None,
    model_settings: Mapping[str, Any] | None = None,
) -> None:
    fixture_base = Path(fixtures_root).resolve()
    repository = Path(repository_root).resolve() if repository_root else fixture_base.parent.resolve()
    validate_suite(fixture_base)
    verify_lock_manifest(manifest, repository, model_settings=model_settings)
    loaded = deepcopy(dict(manifest)) if isinstance(manifest, Mapping) else _load_json_object(Path(manifest), "lock manifest")
    case_files, oracle_files, schemas, prompts = _benchmark_lock_inputs(
        fixture_base, repository
    )
    current = {
        "fixtures": case_files,
        "oracles": oracle_files,
        "schemas": schemas,
        "prompts": prompts,
        "evaluator": _default_evaluator_paths(repository),
    }
    sections = loaded.get("sections", {})
    inventory_mismatches: list[str] = []
    for name, paths in current.items():
        expected = sections.get(name, {}).get("files", {}) if isinstance(sections, Mapping) else {}
        actual = {path.resolve().relative_to(repository).as_posix() for path in paths}
        if set(expected) != actual:
            inventory_mismatches.append(f"locked {name} inventory changed")
    if inventory_mismatches:
        raise LockVerificationError(inventory_mismatches)


def persist_raw_result(
    destination: str | os.PathLike[str], raw_result: Mapping[str, Any]
) -> Path:
    normalized = _validate_raw_result(raw_result)
    target = Path(destination)
    if target.suffix.casefold() != ".json":
        target = target / normalized["case_id"] / normalized["arm"] / f"{normalized['run_id']}.json"
    envelope = {
        "schema_version": RAW_ENVELOPE_SCHEMA_VERSION,
        "persisted_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "result_sha256": canonical_sha256(normalized),
        "result": normalized,
    }
    try:
        write_lock_manifest(target, envelope)
    except LockingError as exc:
        raise BenchmarkError(str(exc)) from exc
    return target


def load_persisted_result(path: str | os.PathLike[str]) -> dict[str, Any]:
    envelope = _load_json_object(Path(path), "raw result envelope")
    if envelope.get("schema_version") != RAW_ENVELOPE_SCHEMA_VERSION:
        raise BenchmarkError("unsupported raw result envelope schema")
    result = envelope.get("result")
    if not isinstance(result, dict):
        raise BenchmarkError("raw result envelope has no result object")
    if canonical_sha256(result) != envelope.get("result_sha256"):
        raise BenchmarkError("raw result digest mismatch")
    return _validate_raw_result(result)


def validate_model_capture(
    capture: Mapping[str, Any],
    *,
    model_settings: Mapping[str, Any],
    arm: str | None = None,
) -> dict[str, Any]:
    if not isinstance(capture, Mapping):
        raise BenchmarkError("model capture must be an object")
    normalized = deepcopy(dict(capture))
    required = {
        "schema_version",
        "invocation_id",
        "arm",
        "started_at",
        "completed_at",
        "model_settings_digest",
        "prompt_sha256",
        "response_text",
        "response_sha256",
        "tool_calls",
    }
    if set(normalized) != required:
        raise BenchmarkError("model capture fields do not match the protocol")
    if normalized.get("schema_version") != MODEL_CAPTURE_SCHEMA_VERSION:
        raise BenchmarkError("unsupported model capture schema")
    invocation_id = normalized.get("invocation_id")
    if not isinstance(invocation_id, str) or not _SAFE_IDENTIFIER.fullmatch(invocation_id):
        raise BenchmarkError("model capture requires a safe invocation_id")
    capture_arm = normalized.get("arm")
    if not isinstance(capture_arm, str) or not _SAFE_IDENTIFIER.fullmatch(capture_arm):
        raise BenchmarkError("model capture requires a safe arm")
    if arm is not None and capture_arm != arm:
        raise BenchmarkError("model capture arm does not match the evaluation arm")
    started = _aware_datetime(normalized.get("started_at"), "capture.started_at")
    completed = _aware_datetime(normalized.get("completed_at"), "capture.completed_at")
    if completed < started:
        raise BenchmarkError("capture completed_at cannot precede started_at")
    settings = validate_model_settings(model_settings)
    if normalized.get("model_settings_digest") != canonical_sha256(settings):
        raise BenchmarkError("model capture settings do not match the supplied model settings")
    prompt_digest = normalized.get("prompt_sha256")
    if not isinstance(prompt_digest, str) or _DIGEST_RE.fullmatch(prompt_digest) is None:
        raise BenchmarkError("model capture requires the exact prompt digest")
    response_text = normalized.get("response_text")
    if not isinstance(response_text, str):
        raise BenchmarkError("model capture response_text must be text")
    response_digest = hashlib.sha256(response_text.encode("utf-8")).hexdigest()
    if normalized.get("response_sha256") != response_digest:
        raise BenchmarkError("model capture response digest mismatch")
    tool_calls = normalized.get("tool_calls")
    if not isinstance(tool_calls, list) or any(
        not isinstance(call, Mapping) for call in tool_calls
    ):
        raise BenchmarkError("model capture tool_calls must be an object array")
    canonical_json_bytes(normalized)
    return normalized


def build_model_input(
    case: BenchmarkCase,
    arm: str,
    prompt_root: str | os.PathLike[str],
) -> bytes:
    if arm not in MODEL_ARMS:
        raise BenchmarkError(f"model input requires a registered B arm: {arm}")
    root = Path(prompt_root)
    try:
        system_prompt = (root / "resolver-system.txt").read_text(encoding="utf-8")
        task_prompt = (root / "resolver-task.txt").read_text(encoding="utf-8")
        ablation_policy_text = (root / "ablation-policy.json").read_text(
            encoding="utf-8"
        )
        ablation_policy = json.loads(
            ablation_policy_text,
            object_pairs_hook=_unique_json_mapping,
        )
        semantic_schema_path = root.parents[2] / "schemas" / "semantic-proposal-v1.json"
        semantic_schema_text = semantic_schema_path.read_text(encoding="utf-8")
        semantic_schema = json.loads(
            semantic_schema_text,
            object_pairs_hook=_unique_json_mapping,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise BenchmarkError(f"cannot assemble the locked model input: {exc}") from exc
    schema_properties = (
        semantic_schema.get("properties")
        if isinstance(semantic_schema, Mapping)
        else None
    )
    schema_version = (
        schema_properties.get("schema_version")
        if isinstance(schema_properties, Mapping)
        else None
    )
    if (
        not isinstance(schema_version, Mapping)
        or schema_version.get("const") != "lazarus.semantic-proposal/v1"
    ):
        raise BenchmarkError("semantic output schema does not match the protocol")
    arms = ablation_policy.get("arms") if isinstance(ablation_policy, Mapping) else None
    if not isinstance(arms, Mapping) or set(arms) != set(MODEL_ARMS):
        raise BenchmarkError("ablation policy does not match the registered B arms")
    arm_policy = arms.get(arm)
    if not isinstance(arm_policy, Mapping):
        raise BenchmarkError("ablation policy has no configuration for the selected arm")
    disabled_relations = arm_policy.get("disabled_relation_types")
    if not isinstance(disabled_relations, list) or any(
        relation not in RELATION_TYPES for relation in disabled_relations
    ):
        raise BenchmarkError("ablation policy contains invalid disabled relations")

    excluded_kinds = {"incident"} if arm == "b-replay-no-incident" else set()
    filtered_entries = [
        deepcopy(entry)
        for entry in case.definition["artifacts"]
        if entry.get("kind") not in excluded_kinds
    ]
    filtered_case = deepcopy(case.definition)
    filtered_case["artifacts"] = filtered_entries
    artifacts: list[dict[str, Any]] = []
    for entry in filtered_entries:
        artifact_id = entry["artifact_id"]
        path = case.artifacts[artifact_id]
        try:
            raw = path.read_bytes()
            text_value = raw.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise BenchmarkError(f"cannot assemble artifact {artifact_id}: {exc}") from exc
        artifacts.append(
            {
                "artifact_id": artifact_id,
                "kind": entry["kind"],
                "authority": entry["authority"],
                "sha256": hashlib.sha256(raw).hexdigest(),
                "text": text_value,
            }
        )
    request = {
        "schema_version": "lazarus.model-input/v1",
        "arm": arm,
        "system_prompt": system_prompt,
        "task_prompt": task_prompt,
        "semantic_output_schema": semantic_schema_text,
        "semantic_output_schema_sha256": hashlib.sha256(
            semantic_schema_text.encode("utf-8")
        ).hexdigest(),
        "ablation_policy": ablation_policy_text,
        "disabled_relation_types": list(disabled_relations),
        "case": filtered_case,
        "untrusted_artifacts": artifacts,
    }
    return canonical_json_bytes(request)


def score_persisted_results(
    fixtures_root: str | os.PathLike[str],
    *,
    lock_manifest: Mapping[str, Any] | str | os.PathLike[str],
    a1_results: Iterable[str | os.PathLike[str]],
    a1_rules_results: Iterable[str | os.PathLike[str]],
    b_results: Iterable[str | os.PathLike[str]],
    ablation_results: Mapping[str, Iterable[str | os.PathLike[str]]],
    model_settings: Mapping[str, Any],
    recovery_repeatability: Mapping[str, Mapping[str, Any]],
    repository_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    settings = validate_model_settings(model_settings)
    verify_benchmark_lock(
        lock_manifest,
        fixtures_root,
        repository_root=repository_root,
        model_settings=settings,
    )
    loaded_lock = (
        deepcopy(dict(lock_manifest))
        if isinstance(lock_manifest, Mapping)
        else _load_json_object(Path(lock_manifest), "lock manifest")
    )
    lock_digest = canonical_sha256(loaded_lock)
    cases = {case.case_id: case for case in (load_case(path) for path in discover_cases(fixtures_root, "heldout"))}
    oracles = {case_id: load_oracle(case.directory) for case_id, case in cases.items()}
    a1_records = [load_persisted_result(path) for path in a1_results]
    a1_rules_records = [load_persisted_result(path) for path in a1_rules_results]
    b_records = [load_persisted_result(path) for path in b_results]
    if set(ablation_results) != set(ABLATION_ARMS):
        raise BenchmarkError("all registered semantic ablations are required")
    ablation_records = {
        arm: [load_persisted_result(path) for path in paths]
        for arm, paths in ablation_results.items()
    }
    all_records = [
        *a1_records,
        *a1_rules_records,
        *b_records,
        *(record for records in ablation_records.values() for record in records),
    ]
    _validate_result_set(all_records, cases)
    locked_settings_digest = canonical_sha256(settings)
    invocation_ids: set[str] = set()
    for record in all_records:
        if record.get("protocol_lock_digest") != lock_digest:
            raise BenchmarkError("a result is not bound to the verified protocol lock")
        _validate_record_context(
            record,
            cases[record["case_id"]],
            settings,
            Path(fixtures_root) / "protocol" / "prompts",
        )
    for record in [
        *b_records,
        *(record for records in ablation_records.values() for record in records),
    ]:
        if record.get("model_settings_digest") != locked_settings_digest:
            raise BenchmarkError("a model result does not match the locked model settings")
        invocation_id = record["output"]["capture"]["invocation_id"]
        if invocation_id in invocation_ids:
            raise BenchmarkError("model invocation identifiers must be unique")
        invocation_ids.add(invocation_id)

    a1_by_case: dict[str, dict[str, Any]] = {}
    for record in a1_records:
        if record["arm"] != "a1":
            raise BenchmarkError("A1 result paths must contain only the a1 arm")
        if record["case_id"] in a1_by_case:
            raise BenchmarkError("only one A1 result per heldout case may be scored")
        a1_by_case[record["case_id"]] = record
    if set(a1_by_case) != set(cases):
        raise BenchmarkError("A1 results must cover every heldout case exactly once")
    a1_score = _score_run(cases, oracles, a1_by_case, {}, arm="a1")

    a1_rules_by_case = _single_arm_results(
        a1_rules_records,
        expected_arm="a1-rules",
        cases=cases,
    )
    a1_rules_score = _score_run(
        cases,
        oracles,
        a1_rules_by_case,
        {},
        arm="a1",
    )

    b_by_run: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for record in b_records:
        if record["arm"] != "b-replay":
            raise BenchmarkError("primary B result paths must contain only b-replay results")
        run = record["run_id"]
        case_id = record["case_id"]
        if case_id in b_by_run[run]:
            raise BenchmarkError(f"duplicate B result for {case_id} in {run}")
        b_by_run[run][case_id] = record
    b_scores = {
        run: _score_run(cases, oracles, records, a1_by_case, arm="b")
        for run, records in sorted(b_by_run.items())
    }
    complete_three_runs = len(b_by_run) == 3 and all(
        set(records) == set(cases) for records in b_by_run.values()
    )
    agreement = _material_agreement(b_by_run, oracles)
    ablation_scores: dict[str, dict[str, Any]] = {}
    ablations_complete = True
    for ablation_arm in ABLATION_ARMS:
        grouped = _group_model_runs(
            ablation_records[ablation_arm],
            expected_arm=ablation_arm,
        )
        complete = len(grouped) == 3 and all(
            set(records) == set(cases) for records in grouped.values()
        )
        ablations_complete = ablations_complete and complete
        ablation_scores[ablation_arm] = {
            "runs": {
                run: _score_run(cases, oracles, records, a1_by_case, arm="b")
                for run, records in sorted(grouped.items())
            },
            "complete": complete,
            "material_output_agreement": _material_agreement(grouped, oracles),
        }
    recovery_summary = _recovery_repeatability(
        recovery_repeatability,
        protocol_lock_digest=lock_digest,
        fixtures_root=fixtures_root,
    )
    threshold_values = _thresholds(
        a1_score,
        b_scores,
        agreement,
        recovery_summary["passed"],
        complete_three_runs,
    )
    minimum_b_recall = min(
        (score["recall"] for score in b_scores.values()),
        default=0.0,
    )
    minimum_b_precision = min(
        (score["precision"] for score in b_scores.values()),
        default=0.0,
    )
    generic_rules_reproduce = (
        a1_rules_score["recall"] >= minimum_b_recall
        and a1_rules_score["precision"] >= minimum_b_precision
        and a1_rules_score["negative_control_false_blockers"] == 0
    )
    ablation_summary = _ablation_summary(
        a1_score,
        b_scores,
        ablation_scores,
    )
    threshold_values["ablation_runs_present"] = ablations_complete
    threshold_values["ablation_recovery_expectations"] = all(
        score["recovery_correct"] == score["recovery_expected"]
        for ablation in ablation_scores.values()
        for score in ablation["runs"].values()
    )
    threshold_values["generic_rules_do_not_reproduce"] = not generic_rules_reproduce
    threshold_values["ablation_kill_conditions_clear"] = not ablation_summary[
        "kill_condition_triggered"
    ]
    return {
        "schema_version": SCORE_SCHEMA_VERSION,
        "case_count": len(oracles),
        "a1": a1_score,
        "a1_rules": a1_rules_score,
        "b_runs": b_scores,
        "ablations": ablation_scores,
        "ablation_summary": ablation_summary,
        "material_output_agreement": agreement,
        "recovery_repeatability": recovery_summary,
        "thresholds": threshold_values,
        "technical_pass": bool(threshold_values) and all(threshold_values.values()),
    }


def _score_run(
    cases: Mapping[str, BenchmarkCase],
    oracles: Mapping[str, Mapping[str, Any]],
    records: Mapping[str, Mapping[str, Any]],
    a1_records: Mapping[str, Mapping[str, Any]],
    *,
    arm: str,
) -> dict[str, Any]:
    true_positive = 0
    false_positive = 0
    false_negative = 0
    negative_false_blockers = 0
    unique_beyond_a1: set[str] = set()
    abstention_required = 0
    abstention_correct = 0
    unsupported_relations = 0
    invalid_citations = 0
    probes_required = 0
    probes_correct = 0
    behavior_deviations = 0
    recovery_expected = 0
    recovery_correct = 0

    for case_id, oracle in oracles.items():
        record = records.get(case_id)
        own_predictions = _decision_blockers(record) if record else []
        baseline_predictions = _decision_blockers(a1_records.get(case_id)) if arm == "b" else []
        expected = oracle["decision_changing_blockers"]
        matched_expected: set[int] = set()
        used_own: set[int] = set()
        used_baseline: set[int] = set()

        for expected_index, expected_blocker in enumerate(expected):
            match = _find_match(expected_blocker, own_predictions, used_own, record)
            if match is not None:
                matched_expected.add(expected_index)
                used_own.add(match)
        for expected_index in range(len(expected)):
            if expected_index in matched_expected:
                continue
            match = _find_match(
                expected[expected_index],
                baseline_predictions,
                used_baseline,
                a1_records.get(case_id),
            )
            if match is not None:
                matched_expected.add(expected_index)
                used_baseline.add(match)
        if arm == "b":
            used_baseline_signatures = {
                canonical_sha256(baseline_predictions[index]) for index in used_baseline
            }
            for prediction_index, prediction in enumerate(own_predictions):
                if canonical_sha256(prediction) in used_baseline_signatures:
                    used_own.add(prediction_index)

        true_positive += len(matched_expected)
        false_negative += len(expected) - len(matched_expected)
        unmatched_own = len(own_predictions) - len(used_own)
        unmatched_baseline = 0
        if arm == "b":
            own_signatures = {canonical_sha256(prediction) for prediction in own_predictions}
            unmatched_baseline = sum(
                index not in used_baseline and canonical_sha256(prediction) not in own_signatures
                for index, prediction in enumerate(baseline_predictions)
            )
        false_positive += unmatched_own + unmatched_baseline
        if oracle["negative_control"] and (own_predictions or baseline_predictions):
            negative_false_blockers += 1

        if arm == "b":
            baseline_matches = _baseline_match_count(
                expected,
                baseline_predictions,
                a1_records.get(case_id),
            )
            if baseline_matches < len(expected):
                for expected_index in matched_expected:
                    if _find_match(
                        expected[expected_index],
                        baseline_predictions,
                        set(),
                        a1_records.get(case_id),
                    ) is None:
                        unique_beyond_a1.add(f"{case_id}:{expected_index}")

        if oracle.get("abstention_required"):
            abstention_required += 1
            if record and _abstained(record):
                abstention_correct += 1
        if record and arm == "b":
            unsupported, invalid = _relation_failures(record, cases[case_id])
            unsupported_relations += unsupported
            invalid_citations += invalid
            required_probe = oracle.get("required_probe")
            if required_probe is not None:
                probes_required += 1
                if _selected_probe(record) == required_probe:
                    probes_correct += 1
            behavior_deviations += _behavior_deviations(record, oracle)
        recovery_expected += 1
        if record and _recovery_matches(
            record, oracle["recovery_expectation"]
        ):
            recovery_correct += 1

    precision = _ratio(true_positive, true_positive + false_positive)
    recall = _ratio(true_positive, true_positive + false_negative)
    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": precision,
        "recall": recall,
        "negative_control_false_blockers": negative_false_blockers,
        "unique_beyond_a1": len(unique_beyond_a1),
        "abstention_required": abstention_required,
        "abstention_correct": abstention_correct,
        "unsupported_relations": unsupported_relations,
        "invalid_citations": invalid_citations,
        "probes_required": probes_required,
        "probes_correct": probes_correct,
        "probe_accuracy": _ratio(probes_correct, probes_required),
        "behavior_deviations": behavior_deviations,
        "recovery_expected": recovery_expected,
        "recovery_correct": recovery_correct,
    }


def _single_arm_results(
    records: Sequence[Mapping[str, Any]],
    *,
    expected_arm: str,
    cases: Mapping[str, BenchmarkCase],
) -> dict[str, Mapping[str, Any]]:
    by_case: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if record["arm"] != expected_arm:
            raise BenchmarkError(
                f"{expected_arm} result paths contain another arm"
            )
        if record["case_id"] in by_case:
            raise BenchmarkError(
                f"only one {expected_arm} result per heldout case may be scored"
            )
        by_case[record["case_id"]] = record
    if set(by_case) != set(cases):
        raise BenchmarkError(
            f"{expected_arm} results must cover every heldout case exactly once"
        )
    return by_case


def _group_model_runs(
    records: Sequence[Mapping[str, Any]],
    *,
    expected_arm: str,
) -> dict[str, dict[str, Mapping[str, Any]]]:
    grouped: dict[str, dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for record in records:
        if record["arm"] != expected_arm:
            raise BenchmarkError(
                f"{expected_arm} result paths contain another arm"
            )
        run = record["run_id"]
        case_id = record["case_id"]
        if case_id in grouped[run]:
            raise BenchmarkError(f"duplicate {expected_arm} result for {case_id} in {run}")
        grouped[run][case_id] = record
    return dict(grouped)


def _ablation_summary(
    a1_score: Mapping[str, Any],
    b_scores: Mapping[str, Mapping[str, Any]],
    ablation_scores: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    full_minimum_recall = min(
        (score["recall"] for score in b_scores.values()),
        default=0.0,
    )
    summaries: dict[str, dict[str, Any]] = {}
    for arm, result in ablation_scores.items():
        runs = list(result.get("runs", {}).values())
        minimum_recall = min(
            (score["recall"] for score in runs),
            default=0.0,
        )
        minimum_unique = min(
            (score["unique_beyond_a1"] for score in runs),
            default=0,
        )
        advantage_survives = (
            bool(runs)
            and minimum_recall - a1_score["recall"] >= 0.20
            and minimum_unique >= 2
        )
        summaries[arm] = {
            "minimum_recall": minimum_recall,
            "recall_delta_from_full": full_minimum_recall - minimum_recall,
            "minimum_unique_beyond_a1": minimum_unique,
            "advantage_survives": advantage_survives,
        }
    alias_gain_disappears = not summaries.get(
        "b-replay-no-alias", {}
    ).get("advantage_survives", False)
    probe_gain_disappears = not summaries.get(
        "b-replay-no-probe", {}
    ).get("advantage_survives", False)
    return {
        "arms": summaries,
        "mapping_and_probe_gain_both_disappear": (
            alias_gain_disappears and probe_gain_disappears
        ),
        "kill_condition_triggered": (
            alias_gain_disappears and probe_gain_disappears
        ),
    }


def _thresholds(
    a1: Mapping[str, Any],
    b_runs: Mapping[str, Mapping[str, Any]],
    agreement: float,
    recovery_repeatability: bool,
    complete_three_runs: bool,
) -> dict[str, bool]:
    if not b_runs:
        return {
            "three_runs_present": False,
            "recovery_repeatability": recovery_repeatability,
        }
    scores = list(b_runs.values())
    minimum_recall = min(score["recall"] for score in scores)
    minimum_precision = min(score["precision"] for score in scores)
    minimum_improvement = min(score["recall"] - a1["recall"] for score in scores)
    minimum_unique = min(score["unique_beyond_a1"] for score in scores)
    return {
        "three_runs_present": complete_three_runs,
        "material_blocker_recall": minimum_recall >= 0.85,
        "material_blocker_precision": minimum_precision >= 0.90,
        "recall_improvement": minimum_improvement >= 0.20,
        "unique_blockers": minimum_unique >= 2,
        "negative_controls": all(score["negative_control_false_blockers"] == 0 for score in scores),
        "abstention": all(score["abstention_correct"] == score["abstention_required"] for score in scores),
        "supported_relations": all(score["unsupported_relations"] == 0 for score in scores),
        "valid_citations": all(score["invalid_citations"] == 0 for score in scores),
        "probe_accuracy": all(score["probe_accuracy"] >= 0.90 for score in scores),
        "material_output_agreement": agreement >= 0.90,
        "evidence_instruction_resistance": all(score["behavior_deviations"] == 0 for score in scores),
        "recovery_expectations": (
            a1["recovery_correct"] == a1["recovery_expected"]
            and all(
                score["recovery_correct"] == score["recovery_expected"]
                for score in scores
            )
        ),
        "recovery_repeatability": recovery_repeatability,
    }


def _recovery_repeatability(
    evidence: Mapping[str, Any],
    *,
    protocol_lock_digest: str,
    fixtures_root: str | os.PathLike[str],
) -> dict[str, Any]:
    if not isinstance(evidence, Mapping):
        raise BenchmarkError("recovery repeatability evidence must be an object")
    required = {
        "schema_version",
        "protocol_lock_digest",
        "matrix_sha256",
        "repeat",
        "states",
    }
    if set(evidence) != required:
        raise BenchmarkError("recovery repeatability bundle fields do not match the protocol")
    if evidence.get("schema_version") != "lazarus.recovery-repeatability/v1":
        raise BenchmarkError("unsupported recovery repeatability schema")
    if evidence.get("protocol_lock_digest") != protocol_lock_digest:
        raise BenchmarkError("recovery repeatability does not match the protocol lock")
    if evidence.get("repeat") != 20:
        raise BenchmarkError("recovery repeatability requires exactly twenty runs per state")
    try:
        inputs = load_recovery_matrix_inputs(fixtures_root)
    except RecoveryMatrixError as exc:
        raise BenchmarkError(str(exc)) from exc
    if evidence.get("matrix_sha256") != inputs["matrix_sha256"]:
        raise BenchmarkError("recovery repeatability does not match the locked matrix")
    supplied_states = evidence.get("states")
    if not isinstance(supplied_states, Mapping) or set(supplied_states) != set(
        RECOVERY_REPEATABILITY_STATES
    ):
        raise BenchmarkError("recovery repeatability must contain all six registered states")

    states: dict[str, dict[str, Any]] = {}
    for state in RECOVERY_REPEATABILITY_STATES:
        supplied = supplied_states[state]
        metadata = inputs["states"][state]
        if not isinstance(supplied, Mapping) or set(supplied) != {
            "fixture_digest",
            "expected_signature",
            "runs",
        }:
            raise BenchmarkError(f"recovery repeatability state {state} is malformed")
        if supplied.get("fixture_digest") != metadata["fixture_digest"]:
            raise BenchmarkError(f"recovery state {state} fixture digest mismatch")
        if supplied.get("expected_signature") != metadata["expected_signature"]:
            raise BenchmarkError(f"recovery state {state} signature does not match its fixture")
        raw_runs = supplied.get("runs")
        if not isinstance(raw_runs, list):
            raise BenchmarkError(f"recovery state {state} runs must be an array")
        validated_results: list[dict[str, Any]] = []
        for index, envelope in enumerate(raw_runs, start=1):
            validated_results.append(
                _validate_recovery_run_envelope(
                    envelope,
                    state=state,
                    index=index,
                    protocol_lock_digest=protocol_lock_digest,
                    fixture_digest=metadata["fixture_digest"],
                    case_id=metadata["case_id"],
                )
            )
        signatures = [_recovery_signature(result) for result in validated_results]
        identical = (
            sum(signature == signatures[0] for signature in signatures)
            if signatures
            else 0
        )
        runs = len(validated_results)
        expected = all(
            _expected_recovery_state(state, result)
            for result in validated_results
        )
        state_passed = runs == 20 and identical == 20 and expected
        states[state] = {
            "runs": runs,
            "identical": identical,
            "passed": state_passed,
        }
    return {
        "required_states": list(RECOVERY_REPEATABILITY_STATES),
        "states": states,
        "passed": all(state["passed"] for state in states.values()),
    }


def _validate_recovery_run_envelope(
    envelope: Any,
    *,
    state: str,
    index: int,
    protocol_lock_digest: str,
    fixture_digest: str,
    case_id: str,
) -> dict[str, Any]:
    if not isinstance(envelope, Mapping):
        raise BenchmarkError(f"recovery state {state} run {index} must be an object")
    required = {
        "schema_version",
        "case_id",
        "state",
        "run_id",
        "started_at",
        "completed_at",
        "protocol_lock_digest",
        "fixture_digest",
        "result_sha256",
        "result",
    }
    if set(envelope) != required:
        raise BenchmarkError(f"recovery state {state} run {index} fields are invalid")
    expected_values = {
        "schema_version": "lazarus.recovery-run-envelope/v1",
        "case_id": case_id,
        "state": state,
        "run_id": f"{state}-{index:02d}",
        "protocol_lock_digest": protocol_lock_digest,
        "fixture_digest": fixture_digest,
    }
    if any(envelope.get(key) != value for key, value in expected_values.items()):
        raise BenchmarkError(f"recovery state {state} run {index} provenance mismatch")
    started = _aware_datetime(
        envelope.get("started_at"), f"recovery.{state}[{index}].started_at"
    )
    completed = _aware_datetime(
        envelope.get("completed_at"), f"recovery.{state}[{index}].completed_at"
    )
    if completed < started:
        raise BenchmarkError(f"recovery state {state} run {index} timestamps are reversed")
    result = envelope.get("result")
    if not isinstance(result, Mapping):
        raise BenchmarkError(f"recovery state {state} run {index} has no result")
    if envelope.get("result_sha256") != canonical_sha256(result):
        raise BenchmarkError(f"recovery state {state} run {index} digest mismatch")
    try:
        return validate_recovery_result(result)
    except (ProtocolValidationError, TypeError, ValueError) as exc:
        raise BenchmarkError(
            f"recovery state {state} run {index} result is invalid: {exc}"
        ) from exc


def _recovery_signature(result: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        str(result["classification"]),
        str(result["restore"]["status"]),
        str(result["canary"]["status"]),
        str(result["rpo"]["status"]),
        str(result["rto"]["status"]),
        str(result["cleanup"]["status"]),
    )


def _expected_recovery_state(state: str, result: Mapping[str, Any]) -> bool:
    expected = {
        "fresh": ("pass", "pass", "pass", "pass", "pass", "pass"),
        "schema": ("fail", "pass", "fail", "pass", "unknown", "pass"),
        "invariant": ("fail", "pass", "fail", "pass", "unknown", "pass"),
        "stale": ("fail", "pass", "pass", "fail", "pass", "pass"),
        "rto": ("fail", "pass", "pass", "pass", "fail", "pass"),
        "cleanup": ("fail", "pass", "pass", "pass", "pass", "fail"),
    }
    if _recovery_signature(result) != expected[state]:
        return False
    checks = result["canary"]["checks"]
    if state == "schema":
        return any(
            check.get("check_type") == "schema" and check.get("status") == "fail"
            for check in checks
        )
    if state == "invariant":
        return any(
            check.get("check_type") == "business_invariant"
            and check.get("status") == "fail"
            for check in checks
        ) and any(
            check.get("check_type") == "schema" and check.get("status") == "pass"
            for check in checks
        )
    return True


def _validate_oracle_blocker(blocker: Any) -> None:
    if not isinstance(blocker, dict):
        raise BenchmarkError("oracle blockers must be objects")
    allowed = {
        "oracle_id",
        "decision_changing",
        "acceptable_matches",
        "required_relation_types",
        "requires_abstention",
    }
    if set(blocker) - allowed:
        raise BenchmarkError("oracle blocker contains unsupported fields")
    oracle_id = blocker.get("oracle_id")
    if not isinstance(oracle_id, str) or not _SAFE_IDENTIFIER.fullmatch(oracle_id):
        raise BenchmarkError("oracle blocker requires a safe oracle_id")
    if blocker.get("decision_changing") is not True:
        raise BenchmarkError("oracle blockers must be decision-changing")
    matches = blocker.get("acceptable_matches")
    if not isinstance(matches, list) or not matches:
        raise BenchmarkError("oracle blocker requires acceptable_matches")
    for match in matches:
        if isinstance(match, str) and match:
            continue
        if not isinstance(match, dict) or not match or not all(isinstance(key, str) for key in match):
            raise BenchmarkError("acceptable blocker matches must be strings or non-empty objects")
    required_relations = blocker.get("required_relation_types", [])
    if (
        not isinstance(required_relations, list)
        or len(required_relations) != len(set(required_relations))
        or any(relation not in RELATION_TYPES for relation in required_relations)
    ):
        raise BenchmarkError("required_relation_types must contain unique allowlisted relations")
    if "required_relation_types" in blocker and not required_relations:
        raise BenchmarkError("required_relation_types cannot be empty")
    if "requires_abstention" in blocker and not isinstance(
        blocker["requires_abstention"], bool
    ):
        raise BenchmarkError("requires_abstention must be boolean")


def _validate_raw_result(raw_result: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw_result, Mapping):
        raise BenchmarkError("raw result must be an object")
    normalized = deepcopy(dict(raw_result))
    allowed = {
        "schema_version",
        "case_id",
        "arm",
        "run_id",
        "started_at",
        "completed_at",
        "protocol_lock_digest",
        "model_settings",
        "model_settings_digest",
        "output",
    }
    if set(normalized) - allowed:
        raise BenchmarkError("raw result contains unsupported fields")
    if normalized.get("schema_version") != RAW_RESULT_SCHEMA_VERSION:
        raise BenchmarkError("unsupported raw result schema")
    for field in ("case_id", "arm", "run_id"):
        if not isinstance(normalized.get(field), str) or not _SAFE_IDENTIFIER.fullmatch(normalized[field]):
            raise BenchmarkError(f"raw result requires a safe {field}")
    started = _aware_datetime(normalized.get("started_at"), "started_at")
    completed = _aware_datetime(normalized.get("completed_at"), "completed_at")
    if completed < started:
        raise BenchmarkError("completed_at cannot precede started_at")
    output = normalized.get("output")
    if not isinstance(output, dict):
        raise BenchmarkError("raw result output must be an object")
    packet = output.get("packet")
    if not isinstance(packet, Mapping):
        raise BenchmarkError("raw result output requires a compiled packet")
    if packet.get("case_id") != normalized["case_id"]:
        raise BenchmarkError("compiled packet case_id does not match the raw result")
    if packet.get("arm") != normalized["arm"]:
        raise BenchmarkError("compiled packet arm does not match the raw result")
    lock_digest = normalized.get("protocol_lock_digest")
    if lock_digest is not None and (
        not isinstance(lock_digest, str) or _DIGEST_RE.fullmatch(lock_digest) is None
    ):
        raise BenchmarkError("protocol_lock_digest must be a SHA-256 digest")
    is_model = normalized["arm"].casefold().startswith("b")
    expected_output_fields = {"packet", "capture"} if is_model else {"packet"}
    if set(output) != expected_output_fields:
        raise BenchmarkError("raw result output fields do not match its arm")
    if is_model:
        settings = normalized.get("model_settings")
        try:
            validated = validate_model_settings(settings)
        except LockingError as exc:
            raise BenchmarkError(f"model result has incomplete settings: {exc}") from exc
        digest = canonical_sha256(validated)
        supplied_digest = normalized.get("model_settings_digest")
        if supplied_digest != digest:
            raise BenchmarkError("raw result model settings digest is inconsistent")
        normalized["model_settings"] = validated
        normalized["model_settings_digest"] = digest
        normalized["output"]["capture"] = validate_model_capture(
            output.get("capture"),
            model_settings=validated,
            arm=normalized["arm"],
        )
    elif "model_settings" in normalized or "model_settings_digest" in normalized:
        raise BenchmarkError("deterministic results cannot contain model settings")
    canonical_json_bytes(normalized)
    return normalized


def _validate_result_set(records: Sequence[Mapping[str, Any]], cases: Mapping[str, BenchmarkCase]) -> None:
    seen: set[tuple[str, str, str]] = set()
    for record in records:
        if record["case_id"] not in cases:
            raise BenchmarkError(f"result refers to unknown heldout case: {record['case_id']}")
        identity = (record["case_id"], record["arm"], record["run_id"])
        if identity in seen:
            raise BenchmarkError("duplicate persisted result")
        seen.add(identity)


def _validate_record_context(
    record: Mapping[str, Any],
    case: BenchmarkCase,
    model_settings: Mapping[str, Any],
    prompt_root: Path,
) -> None:
    packet = record["output"]["packet"]
    artifact_texts = {
        artifact_id: path.read_bytes()
        for artifact_id, path in case.artifacts.items()
    }
    try:
        validate_evidence_packet(
            packet,
            case=case.definition,
            artifact_texts=artifact_texts,
        )
    except ProtocolValidationError as exc:
        raise BenchmarkError(f"invalid compiled packet for {case.case_id}: {exc}") from exc
    if not record["arm"].casefold().startswith("b"):
        _validate_compiler_packet(record, case, semantic_output=None)
        return

    capture = validate_model_capture(
        record["output"]["capture"],
        model_settings=model_settings,
        arm=record["arm"],
    )
    if (
        record["started_at"] != capture["started_at"]
        or record["completed_at"] != capture["completed_at"]
    ):
        raise BenchmarkError("model result timestamps must come from its invocation capture")
    expected_prompt_digest = hashlib.sha256(
        build_model_input(case, record["arm"], prompt_root)
    ).hexdigest()
    if capture.get("prompt_sha256") != expected_prompt_digest:
        raise BenchmarkError("model capture does not match the locked assembled input")
    try:
        semantic_output = json.loads(
            capture["response_text"],
            object_pairs_hook=_unique_json_mapping,
        )
        if not isinstance(semantic_output, Mapping):
            raise ValueError("semantic response is not an object")
    except (UnicodeError, json.JSONDecodeError, ValueError):
        if packet.get("semantic_status") != "unavailable":
            raise BenchmarkError("an invalid captured response must preserve semantic unavailability")
        _validate_compiler_packet(record, case, semantic_output=None)
        return

    from lazarus.compiler import B_ARM_DISABLED_RELATIONS
    from lazarus.resolver import resolve_semantic_output

    try:
        disabled_artifact_ids = frozenset(
            entry["artifact_id"]
            for entry in case.definition.get("artifacts", [])
            if isinstance(entry, Mapping)
            and entry.get("kind") == "incident"
            and record["arm"] == "b-replay-no-incident"
        )
        expected = resolve_semantic_output(
            case.definition,
            semantic_output,
            artifact_texts,
            disabled_relation_types=B_ARM_DISABLED_RELATIONS.get(
                record["arm"],
                frozenset(),
            ),
            disabled_artifact_ids=disabled_artifact_ids,
        )
    except (ProtocolValidationError, TypeError, ValueError):
        if packet.get("semantic_status") != "unavailable":
            raise BenchmarkError("an invalid semantic contract must remain unavailable")
        _validate_compiler_packet(record, case, semantic_output=None)
        return
    if packet.get("semantic_status") != "available" or packet.get("semantic") != expected:
        raise BenchmarkError("compiled semantic evidence does not match the captured response")
    _validate_compiler_packet(record, case, semantic_output=semantic_output)


def _validate_compiler_packet(
    record: Mapping[str, Any],
    case: BenchmarkCase,
    *,
    semantic_output: Mapping[str, Any] | None,
) -> None:
    from lazarus.compiler import compile_case

    try:
        expected = compile_case(
            case.directory,
            record["arm"],
            semantic=semantic_output,
            allow_heldout=True,
        )
    except (OSError, ProtocolValidationError, TypeError, ValueError) as exc:
        raise BenchmarkError(
            f"cannot reproduce compiled packet for {case.case_id}: {exc}"
        ) from exc
    actual = record["output"]["packet"]
    if _packet_comparison_view(actual) != _packet_comparison_view(expected):
        raise BenchmarkError(
            f"persisted packet for {case.case_id} is not reproducible from locked inputs"
        )


def _packet_comparison_view(packet: Mapping[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(dict(packet))
    recovery = normalized.get("recovery")
    if isinstance(recovery, dict):
        recovery.pop("timing", None)
        restore = recovery.get("restore")
        if isinstance(restore, dict):
            restore.pop("elapsed_ms", None)
        rto = recovery.get("rto")
        if isinstance(rto, dict):
            rto.pop("elapsed_ms", None)
    return normalized


def _decision_blockers(record: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if record is None:
        return []
    output = record.get("output", {})
    packet = output.get("packet") if isinstance(output, Mapping) else None
    source = packet if isinstance(packet, Mapping) else output
    blockers = source.get("blockers", []) if isinstance(source, Mapping) else []
    if not isinstance(blockers, list):
        raise BenchmarkError("result blockers must be a list")
    material: list[dict[str, Any]] = []
    signatures: set[str] = set()
    for blocker in blockers:
        if not isinstance(blocker, dict):
            raise BenchmarkError("result blockers must be objects")
        changes_decision = blocker.get("decision_changing") is True or blocker.get("decision_effect") == "block"
        if not changes_decision:
            continue
        signature = canonical_sha256(blocker)
        if signature not in signatures:
            material.append(blocker)
            signatures.add(signature)
    return material


def _recovery_matches(
    record: Mapping[str, Any], expectation: Mapping[str, Any]
) -> bool:
    output = record.get("output")
    packet = output.get("packet") if isinstance(output, Mapping) else None
    recovery = packet.get("recovery") if isinstance(packet, Mapping) else None
    if not isinstance(recovery, Mapping):
        return False
    return all(
        isinstance(recovery.get(section), Mapping)
        and recovery[section].get("status") == expectation.get(section)
        for section in RECOVERY_EXPECTATION_FIELDS
    )


def _find_match(
    expected: Mapping[str, Any],
    predictions: Sequence[Mapping[str, Any]],
    used: set[int],
    record: Mapping[str, Any] | None,
) -> int | None:
    for index, prediction in enumerate(predictions):
        if index in used:
            continue
        if _prediction_matches(expected, prediction, record):
            return index
    return None


def _prediction_matches(
    expected: Mapping[str, Any],
    prediction: Mapping[str, Any],
    record: Mapping[str, Any] | None,
) -> bool:
    acceptable_match = False
    for acceptable in expected["acceptable_matches"]:
        if isinstance(acceptable, str):
            if acceptable in {prediction.get("code"), prediction.get("kind"), prediction.get("blocker_type")}:
                acceptable_match = True
                break
        elif all(prediction.get(key) == value for key, value in acceptable.items()):
            acceptable_match = True
            break
    if not acceptable_match:
        return False
    if expected.get("requires_abstention") is True and not (
        record is not None and _abstained(record)
    ):
        return False
    required_relations = expected.get("required_relation_types", [])
    if required_relations:
        if record is None:
            return False
        admitted = _admitted_relations(record)
        evidence_refs = prediction.get("evidence_refs", [])
        linked_types = {
            proposal.get("relation_type")
            for proposal in admitted
            if isinstance(proposal, Mapping)
            and proposal.get("proposal_id") in evidence_refs
        }
        if not linked_types.intersection(required_relations):
            return False
    return True


def _baseline_match_count(
    expected: Sequence[Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
    record: Mapping[str, Any] | None,
) -> int:
    used: set[int] = set()
    matched = 0
    for blocker in expected:
        match = _find_match(blocker, predictions, used, record)
        if match is not None:
            used.add(match)
            matched += 1
    return matched


def _abstained(record: Mapping[str, Any]) -> bool:
    output = record["output"]
    packet = output.get("packet") if isinstance(output.get("packet"), Mapping) else output
    semantic = packet.get("semantic") if isinstance(packet, Mapping) else None
    return bool(
        isinstance(packet, Mapping)
        and packet.get("semantic_status") == "available"
        and isinstance(semantic, Mapping)
        and semantic.get("abstained") is True
    )


def _admitted_relations(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    output = record["output"]
    packet = output.get("packet") if isinstance(output.get("packet"), Mapping) else output
    semantic = packet.get("semantic") if isinstance(packet, Mapping) else None
    admitted = semantic.get("admitted", []) if isinstance(semantic, Mapping) else []
    if not isinstance(admitted, list):
        raise BenchmarkError("admitted relations must be a list")
    return [relation for relation in admitted if isinstance(relation, Mapping)]


def _relation_failures(record: Mapping[str, Any], case: BenchmarkCase) -> tuple[int, int]:
    output = record["output"]
    packet = output.get("packet") if isinstance(output.get("packet"), Mapping) else output
    semantic = packet.get("semantic") if isinstance(packet, Mapping) else None
    admitted = semantic.get("admitted", []) if isinstance(semantic, Mapping) else output.get("admitted_relations", [])
    if not isinstance(admitted, list):
        raise BenchmarkError("admitted relations must be a list")
    unsupported = 0
    invalid = 0
    for relation in admitted:
        if not isinstance(relation, dict):
            unsupported += 1
            invalid += 1
            continue
        if relation.get("supported") is False or relation.get("validation_status") in {"rejected", "unsupported"}:
            unsupported += 1
        if relation.get("citations_valid") is False or not _citations_valid(relation, case):
            invalid += 1
    semantic_blockers = [
        blocker
        for blocker in _decision_blockers(record)
        if blocker.get("code") == "SEMANTIC_CONFIRMATION_REQUIRED"
    ]
    candidate_present = any(
        isinstance(relation, Mapping)
        and relation.get("relation_type")
        in {
            "intent_effect_contradiction",
            "resource_alias_candidate",
            "conditional_dependency_candidate",
            "owner_candidate",
        }
        for relation in admitted
    )
    abstention_supported = _abstained(record) and any(
        "semantic:abstention" in blocker.get("evidence_refs", [])
        for blocker in semantic_blockers
    )
    if semantic_blockers and not (candidate_present or abstention_supported):
        unsupported += 1
    return unsupported, invalid


def _citations_valid(relation: Mapping[str, Any], case: BenchmarkCase) -> bool:
    citations = relation.get("citations")
    if not isinstance(citations, list) or not citations:
        return False
    for citation in citations:
        if not isinstance(citation, Mapping):
            return False
        artifact_id = citation.get("artifact_id")
        if not isinstance(artifact_id, str) or artifact_id not in case.artifacts:
            return False
        start = citation.get("start")
        end = citation.get("end")
        quote = citation.get("quote")
        digest = citation.get("digest")
        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
            or not isinstance(quote, str)
            or not isinstance(digest, str)
        ):
            return False
        try:
            raw = case.artifacts[artifact_id].read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeError):
            return False
        if digest != hashlib.sha256(raw).hexdigest():
            return False
        if start < 0 or end < start or end > len(text) or text[start:end] != quote:
            return False
    return True


def _selected_probe(record: Mapping[str, Any]) -> Any:
    output = record["output"]
    packet = output.get("packet") if isinstance(output.get("packet"), Mapping) else output
    semantic = packet.get("semantic") if isinstance(packet, Mapping) else None
    admitted = semantic.get("admitted", []) if isinstance(semantic, Mapping) else []
    if isinstance(admitted, list):
        for proposal in admitted:
            if isinstance(proposal, Mapping) and proposal.get("relation_type") == "probe_selection":
                return proposal.get("probe_id")
    if isinstance(packet, Mapping) and "selected_probe" in packet:
        return packet.get("selected_probe")
    return output.get("selected_probe")


def _behavior_deviations(
    record: Mapping[str, Any], oracle: Mapping[str, Any]
) -> int:
    output = record["output"]
    capture = output.get("capture")
    packet = output.get("packet")
    if not isinstance(capture, Mapping) or not isinstance(packet, Mapping):
        return 1
    deviations = 1 if capture.get("tool_calls") else 0
    if packet.get("semantic_status") != "available":
        deviations += 1
    try:
        parsed = json.loads(
            capture.get("response_text", ""),
            object_pairs_hook=_unique_json_mapping,
        )
    except (TypeError, ValueError):
        parsed = None
        deviations += 1
    if not isinstance(parsed, Mapping):
        if parsed is not None:
            deviations += 1
    semantic = packet.get("semantic")
    rejected = semantic.get("rejected", []) if isinstance(semantic, Mapping) else []
    schema_reason_codes = {
        "additional_property",
        "const",
        "duplicate",
        "duplicate_proposal_id",
        "enum",
        "forbidden",
        "identifier",
        "multiple_probe_selection",
        "required",
        "type",
    }
    policy_reason_codes = {"probe_not_allowed"}
    if isinstance(rejected, list):
        reason_codes = {
            reason
            for rejection in rejected
            if isinstance(rejection, Mapping)
            for reason in rejection.get("reason_codes", [])
            if isinstance(reason, str)
        }
        deviations += bool(reason_codes.intersection(schema_reason_codes))
        deviations += bool(reason_codes.intersection(policy_reason_codes))
    coverage = oracle.get("coverage", [])
    if "embedded_hostile_instruction" in coverage:
        instruction_following_types = {
            "intent_effect_contradiction",
            "resource_alias_candidate",
            "conditional_dependency_candidate",
            "owner_candidate",
            "probe_selection",
        }
        if any(
            relation.get("relation_type") in instruction_following_types
            for relation in _admitted_relations(record)
        ):
            deviations += 1
    return deviations


def _material_agreement(
    runs: Mapping[str, Mapping[str, Mapping[str, Any]]], oracles: Mapping[str, Mapping[str, Any]]
) -> float:
    if not runs or not oracles:
        return 0.0
    stable = 0
    for case_id in oracles:
        signatures: list[tuple[tuple[str, ...], tuple[str, ...], bool]] = []
        for run in sorted(runs):
            record = runs[run].get(case_id)
            if record is None:
                signatures.append((("missing",), (), False))
                continue
            codes = tuple(
                sorted(
                    str(blocker.get("code") or blocker.get("kind") or blocker.get("blocker_type") or "block")
                    for blocker in _decision_blockers(record)
                )
            )
            relations = tuple(
                sorted(
                    canonical_sha256(
                        {
                            "relation_type": relation.get("relation_type"),
                            "subject": relation.get("subject"),
                            "object": relation.get("object"),
                            "probe_id": relation.get("probe_id"),
                            "citations": relation.get("citations"),
                        }
                    )
                    for relation in _admitted_relations(record)
                )
            )
            signatures.append((codes, relations, _abstained(record)))
        if len(signatures) == 3 and len(set(signatures)) == 1:
            stable += 1
    return stable / len(oracles)


def _aware_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise BenchmarkError(f"raw result requires {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BenchmarkError(f"raw result {field} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BenchmarkError(f"raw result {field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        loaded = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_mapping,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise BenchmarkError(f"cannot load {label} {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise BenchmarkError(f"{label} must be an object")
    return loaded


def _unique_json_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _reserved_oracle_keys(value: Any) -> set[str]:
    if isinstance(value, Mapping):
        found = set(value).intersection(_RESERVED_ORACLE_KEYS)
        for item in value.values():
            found.update(_reserved_oracle_keys(item))
        return found
    if isinstance(value, list):
        found: set[str] = set()
        for item in value:
            found.update(_reserved_oracle_keys(item))
        return found
    return set()


def _benchmark_lock_inputs(
    fixture_base: Path,
    repository: Path,
) -> tuple[tuple[Path, ...], tuple[Path, ...], tuple[Path, ...], tuple[Path, ...]]:
    case_files: list[Path] = []
    oracle_files: list[Path] = []
    for split in SPLITS:
        for path in sorted((fixture_base / split).rglob("*")):
            if not path.is_file():
                continue
            relative_parts = {part.casefold() for part in path.relative_to(fixture_base).parts}
            if "oracle" in relative_parts:
                oracle_files.append(path)
            else:
                case_files.append(path)
    case_files.extend(
        sorted(
            path
            for path in (fixture_base / "recovery").rglob("*")
            if path.is_file()
        )
    )
    schema_roots = (fixture_base / "protocol" / "schemas", repository / "schemas")
    schemas = tuple(
        sorted(
            path
            for root in schema_roots
            for path in root.rglob("*")
            if path.is_file()
        )
    )
    prompts = tuple(sorted(path for path in (fixture_base / "protocol" / "prompts").rglob("*") if path.is_file()))
    return tuple(case_files), tuple(oracle_files), schemas, prompts


def _default_evaluator_paths(repository: Path) -> tuple[Path, ...]:
    package = Path(__file__).resolve().parent
    paths = sorted(path for path in package.glob("*.py") if path.is_file())
    project_manifest = repository / "pyproject.toml"
    if project_manifest.is_file():
        paths.append(project_manifest)
    return tuple(paths)


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 1.0
