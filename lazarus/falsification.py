from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import gc
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from typing import Any

from lazarus.benchmark import (
    ABLATION_ARMS,
    BenchmarkCase,
    _score_run,
    build_model_input,
    discover_cases,
    load_case,
    load_oracle,
    persist_raw_result,
    score_persisted_results,
)
from lazarus.compiler import compile_case
from lazarus.execution import (
    build_digest_chain_record,
    build_execution_plan,
    sha256_json,
    validate_execution_inventory,
    verify_digest_chain_record,
    write_immutable_bytes,
    write_immutable_json,
    write_score_receipt,
)
from lazarus.gate import (
    build_calibration_plan,
    capture_calibration_inputs,
    capture_execution_plan,
)
from lazarus.gemini import GEMINI_ENDPOINT, Transport, project_response_schema
from lazarus.locking import (
    build_calibration_lock_manifest,
    build_lock_manifest_v2,
    canonical_sha256,
    file_sha256,
    verify_calibration_lock_manifest,
    verify_lock_manifest,
)
from lazarus.protocol import ProtocolValidationError
from lazarus.recovery import load_recovery_matrix_inputs, run_recovery_matrix
from lazarus.suite import (
    create_sealing_key,
    decrypt_oracles,
    generate_fresh_suite,
    seal_oracles,
)


CALIBRATION_INDEX_SCHEMA_VERSION = "lazarus.calibration-index/v2"
CALIBRATION_SCORE_SCHEMA_VERSION = "lazarus.calibration-score/v1"
RUN_SUMMARY_SCHEMA_VERSION = "lazarus.falsification-summary/v1"
EXPECTED_GENERATION_CALLS = 184
CALIBRATION_CASE_IDS = ("cal-01", "cal-02", "cal-03", "cal-04")

Progress = Callable[[str, int, int], None]


class FalsificationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FalsificationOutcome:
    run_root: Path
    summary: dict[str, Any]


def build_registered_model_settings(repository_root: str | os.PathLike[str]) -> dict[str, Any]:
    repository = Path(repository_root).resolve()
    schema_path = repository / "schemas" / "semantic-proposal-v1.json"
    try:
        schema = json.loads(
            schema_path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_mapping,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise FalsificationError(f"cannot load the semantic response schema: {exc}") from exc
    if not isinstance(schema, Mapping):
        raise FalsificationError("semantic response schema must be an object")
    response_schema_digest = canonical_sha256(project_response_schema(schema))
    return {
        "provider": "gemini-developer-api",
        "api_version": "v1beta",
        "endpoint": GEMINI_ENDPOINT,
        "model": "gemini-3.5-flash",
        "resolved_model_version": "3.5-flash-05-2026",
        "parameters": {
            "temperature": 1.0,
            "top_p": 1.0,
            "max_output_tokens": 1024,
            "candidate_count": 1,
            "response_mime_type": "application/json",
            "response_schema_sha256": response_schema_digest,
        },
        "thinking": {"level": "MEDIUM", "include_thoughts": False},
        "request": {
            "store": False,
            "service_tier": "standard",
            "timeout_seconds": 120,
            "safety_settings": "provider-default",
            "tools": [],
        },
        "retry": {"max_attempts": 1, "backoff_seconds": 0},
    }


def run_registered_falsification(
    repository_root: str | os.PathLike[str],
    run_root: str | os.PathLike[str],
    *,
    api_key: str,
    transport: Transport | None = None,
    progress: Progress | None = None,
    require_exact_main: bool = True,
) -> FalsificationOutcome:
    repository = Path(repository_root).resolve()
    destination = Path(run_root).resolve()
    try:
        destination.relative_to(repository)
    except ValueError as exc:
        raise FalsificationError("run root must be inside the locked repository") from exc
    if destination.exists() or destination.is_symlink():
        raise FalsificationError("run root must not already exist")
    _verify_repository(repository, require_exact_main=require_exact_main)
    destination.mkdir(parents=True, mode=0o700)
    root = destination.resolve()
    control = root / "control"
    calibration_root = root / "calibration-run"
    execution_root = root / "execution"
    custody = root / "custody"
    runtime = root / "runtime"
    for directory in (control, calibration_root, execution_root, custody, runtime):
        directory.mkdir(mode=0o700)

    settings = build_registered_model_settings(repository)
    write_immutable_json(control / "model-settings.json", settings)
    _notify(progress, "calibration_prepare", 0, 4)
    calibration_index = _run_calibration(
        repository,
        calibration_root,
        control,
        settings,
        api_key=api_key,
        transport=transport,
        progress=progress,
    )
    if calibration_index.get("passed") is not True:
        summary = _summary(
            repository,
            settings,
            generation_calls=4,
            calibration=calibration_index,
            lock_manifest=None,
            score=None,
            disposition="calibration_failed",
        )
        write_immutable_json(control / "summary.json", summary)
        return FalsificationOutcome(root, summary)

    _notify(progress, "suite_prepare", 0, 1)
    generated = generate_fresh_suite(
        runtime / "public-suite",
        calibration_index=calibration_index,
    )
    key_path = create_sealing_key(custody / "oracle.key")
    sealed_path = seal_oracles(
        generated.oracles,
        key_path,
        custody / "oracles.json.gpg",
    )
    os.chmod(sealed_path, 0o400)
    suite_manifest = deepcopy(generated.manifest)
    suite_attestation = deepcopy(generated.attestation)
    public_suite_root = generated.root
    del generated
    gc.collect()

    fixtures_root, schemas_root = _assemble_runtime_inputs(
        repository,
        runtime,
        public_suite_root,
    )
    case_ids = tuple(
        sorted(load_case(path).case_id for path in discover_cases(fixtures_root, "heldout"))
    )
    plan = build_execution_plan(case_ids)
    _prepare_model_inputs(execution_root, fixtures_root, plan)

    fixture_paths = (
        tuple(sorted(path for path in fixtures_root.rglob("*") if path.is_file()))
        + tuple(
            sorted(path for path in calibration_root.rglob("*") if path.is_file())
        )
        + (
            control / "model-settings.json",
            control / "calibration-lock.json",
            control / "calibration-index.json",
            public_suite_root / "suite-manifest.json",
            sealed_path,
        )
    )
    schema_paths = tuple(
        sorted(path for path in schemas_root.rglob("*") if path.is_file())
    ) + tuple(
        sorted(
            path
            for path in (fixtures_root / "protocol" / "schemas").rglob("*")
            if path.is_file()
        )
    )
    prompt_paths = tuple(
        sorted(
            path
            for path in (fixtures_root / "protocol" / "prompts").rglob("*")
            if path.is_file()
        )
    )
    evaluator_paths = _evaluator_paths(repository)
    sealed_digest = file_sha256(sealed_path)
    lock_manifest = build_lock_manifest_v2(
        repository,
        execution_root=execution_root,
        fixtures=fixture_paths,
        schemas=schema_paths,
        prompts=prompt_paths,
        evaluator=evaluator_paths,
        prepared_inputs=(entry["path"] for entry in plan["prepared_inputs"]),
        model_settings=settings,
        execution_plan=plan,
        calibration_index=calibration_index,
        suite_manifest=suite_manifest,
        suite_attestation=suite_attestation,
        sealed_oracle_digest=sealed_digest,
    )
    write_immutable_json(control / "benchmark-lock.json", lock_manifest)
    _verify_final_lock(
        lock_manifest,
        repository,
        execution_root,
        settings,
        plan,
        calibration_index,
        suite_manifest,
        suite_attestation,
        sealed_digest,
    )
    lock_digest = canonical_sha256(lock_manifest)
    _notify(progress, "heldout_capture", 0, 180)
    capture_execution_plan(
        execution_root,
        plan,
        lock_manifest=lock_manifest,
        model_settings=settings,
        repository_root=repository,
        sealed_oracle_digest=sealed_digest,
        api_key=api_key,
        transport=transport,
        progress=(
            (lambda completed, total: _notify(progress, "heldout_capture", completed, total))
            if progress is not None
            else None
        ),
    )

    _notify(progress, "evaluation", 0, 204)
    recovery_bundle = _evaluate_plan(
        execution_root,
        fixtures_root,
        plan,
        lock_manifest,
        settings,
        progress=progress,
    )
    inventory = validate_execution_inventory(
        execution_root,
        plan,
        include_score=False,
    )
    for evaluation in plan["evaluations"]:
        if evaluation["invocation_id"] is None:
            continue
        chain = _load_json(execution_root / evaluation["chain_path"], "digest chain")
        verify_digest_chain_record(chain, evaluation, execution_root)

    if file_sha256(sealed_path) != sealed_digest:
        raise FalsificationError("sealed oracle bundle no longer matches the lock")
    _verify_final_lock(
        lock_manifest,
        repository,
        execution_root,
        settings,
        plan,
        calibration_index,
        suite_manifest,
        suite_attestation,
        sealed_digest,
    )
    oracles = decrypt_oracles(sealed_path, key_path)
    try:
        score = _score_execution(
            fixtures_root,
            execution_root,
            plan,
            lock_manifest,
            settings,
            recovery_bundle,
            repository,
            oracles,
        )
    finally:
        oracles = {}
        gc.collect()
    inventory_digest = sha256_json(inventory)
    write_score_receipt(
        execution_root,
        plan,
        lock_digest=lock_digest,
        inventory_digest=inventory_digest,
        score=score,
    )
    validate_execution_inventory(execution_root, plan, include_score=True)
    summary = _summary(
        repository,
        settings,
        generation_calls=EXPECTED_GENERATION_CALLS,
        calibration=calibration_index,
        lock_manifest=lock_manifest,
        score=score,
        disposition="technical_pass" if score["technical_pass"] else "technical_fail",
    )
    write_immutable_json(control / "summary.json", summary)
    return FalsificationOutcome(root, summary)


def _run_calibration(
    repository: Path,
    calibration_root: Path,
    control: Path,
    settings: Mapping[str, Any],
    *,
    api_key: str,
    transport: Transport | None,
    progress: Progress | None,
) -> dict[str, Any]:
    fixtures_root = repository / "fixtures"
    cases = {
        case.case_id: case
        for case in (
            load_case(path) for path in discover_cases(fixtures_root, "calibration")
        )
    }
    if tuple(sorted(cases)) != CALIBRATION_CASE_IDS:
        raise FalsificationError("calibration cases do not match the registered inventory")
    input_entries = [
        {
            "case_id": case_id,
            "arm": "b-replay",
            "path": f"calibration-inputs/{case_id}.json",
        }
        for case_id in CALIBRATION_CASE_IDS
    ]
    for entry in input_entries:
        payload = build_model_input(
            cases[entry["case_id"]],
            "b-replay",
            fixtures_root / "protocol" / "prompts",
        )
        write_immutable_bytes(calibration_root / entry["path"], payload)
    calibration_plan = build_calibration_plan()
    case_paths: list[Path] = []
    oracle_paths: list[Path] = []
    for case in cases.values():
        for path in sorted(case.directory.rglob("*")):
            if not path.is_file():
                continue
            if "oracle" in {part.casefold() for part in path.relative_to(case.directory).parts}:
                oracle_paths.append(path)
            else:
                case_paths.append(path)
    schemas = tuple(
        sorted(path for path in (repository / "schemas").rglob("*") if path.is_file())
    ) + tuple(
        sorted(
            path
            for path in (fixtures_root / "protocol" / "schemas").rglob("*")
            if path.is_file()
        )
    )
    prompts = tuple(
        sorted(
            path
            for path in (fixtures_root / "protocol" / "prompts").rglob("*")
            if path.is_file()
        )
    )
    lock = build_calibration_lock_manifest(
        repository,
        execution_root=calibration_root,
        fixtures=case_paths,
        oracles=oracle_paths,
        schemas=schemas,
        prompts=prompts,
        evaluator=_evaluator_paths(repository),
        prepared_inputs=(entry["path"] for entry in input_entries),
        model_settings=settings,
        calibration_plan=calibration_plan,
    )
    write_immutable_json(control / "calibration-lock.json", lock)
    verify_calibration_lock_manifest(
        lock,
        repository,
        execution_root=calibration_root,
        model_settings=settings,
        calibration_plan=calibration_plan,
    )
    capture_index = capture_calibration_inputs(
        calibration_root,
        input_entries,
        lock_manifest=lock,
        model_settings=settings,
        repository_root=repository,
        api_key=api_key,
        transport=transport,
        progress=(
            (lambda completed, total: _notify(progress, "calibration_capture", completed, total))
            if progress is not None
            else None
        ),
    )
    results: dict[str, str] = {}
    records: dict[str, dict[str, Any]] = {}
    lock_digest = canonical_sha256(lock)
    for sequence, case_id in enumerate(CALIBRATION_CASE_IDS, start=1):
        capture_path = calibration_root / f"calibration/calibration-{sequence:03d}/capture.json"
        capture = _load_json(capture_path, "calibration capture")
        semantic = _semantic_response(capture)
        packet = _compile_semantic(cases[case_id], "b-replay", semantic, allow_heldout=False)
        raw = _raw_result(
            case_id=case_id,
            arm="b-replay",
            run_id="calibration",
            packet=packet,
            lock_digest=lock_digest,
            settings=settings,
            capture=capture,
        )
        result_path = calibration_root / f"calibration/calibration-{sequence:03d}/result.json"
        persist_raw_result(result_path, raw)
        os.chmod(result_path, 0o400)
        relative = result_path.relative_to(calibration_root).as_posix()
        results[relative] = file_sha256(result_path)
        records[case_id] = raw
    oracles = {case_id: load_oracle(cases[case_id].directory) for case_id in CALIBRATION_CASE_IDS}
    a1_records = {
        case_id: {
            "output": {
                "packet": compile_case(cases[case_id].directory, "a1")
            }
        }
        for case_id in CALIBRATION_CASE_IDS
    }
    metrics = _score_run(cases, oracles, records, a1_records, arm="b")
    criteria = {
        "four_results": set(records) == set(CALIBRATION_CASE_IDS),
        "true_positive": metrics["true_positive"] == 4,
        "false_positive": metrics["false_positive"] == 0,
        "false_negative": metrics["false_negative"] == 0,
        "precision": metrics["precision"] == 1.0,
        "recall": metrics["recall"] == 1.0,
        "unique_beyond_a1": metrics["unique_beyond_a1"] == 3,
        "abstention": metrics["abstention_correct"] == metrics["abstention_required"] == 1,
        "supported_relations": metrics["unsupported_relations"] == 0,
        "valid_citations": metrics["invalid_citations"] == 0,
        "probe": metrics["probes_correct"] == metrics["probes_required"] == 1,
        "behavior": metrics["behavior_deviations"] == 0,
        "recovery": metrics["recovery_correct"] == metrics["recovery_expected"] == 4,
        "unique_invocations": len(
            {capture["invocation_id"] for capture in (_load_json(calibration_root / f"calibration/calibration-{index:03d}/capture.json", "calibration capture") for index in range(1, 5))}
        ) == 4,
        "unique_responses": len(
            {capture["response_id"] for capture in (_load_json(calibration_root / f"calibration/calibration-{index:03d}/capture.json", "calibration capture") for index in range(1, 5))}
        ) == 4,
    }
    score = {
        "schema_version": CALIBRATION_SCORE_SCHEMA_VERSION,
        "metrics": metrics,
        "criteria": criteria,
        "passed": all(criteria.values()),
    }
    index = {
        "schema_version": CALIBRATION_INDEX_SCHEMA_VERSION,
        "passed": score["passed"],
        "calibration_lock": _bound(lock),
        "capture_index": _bound(capture_index),
        "results": _bound(dict(sorted(results.items()))),
        "score": _bound(score),
    }
    write_immutable_json(control / "calibration-index.json", index)
    return index


def _assemble_runtime_inputs(
    repository: Path,
    runtime: Path,
    public_suite_root: Path,
) -> tuple[Path, Path]:
    fixtures_root = runtime / "fixtures"
    schemas_root = runtime / "schemas"
    fixtures_root.mkdir()
    shutil.copytree(repository / "fixtures" / "protocol", fixtures_root / "protocol")
    shutil.copytree(repository / "fixtures" / "recovery", fixtures_root / "recovery")
    shutil.copytree(public_suite_root / "heldout", fixtures_root / "heldout")
    shutil.copytree(repository / "schemas", schemas_root)
    return fixtures_root, schemas_root


def _prepare_model_inputs(
    execution_root: Path,
    fixtures_root: Path,
    plan: Mapping[str, Any],
) -> None:
    cases = {
        case.case_id: case
        for case in (load_case(path) for path in discover_cases(fixtures_root, "heldout"))
    }
    for entry in plan["prepared_inputs"]:
        payload = build_model_input(
            cases[entry["case_id"]],
            entry["arm"],
            fixtures_root / "protocol" / "prompts",
        )
        write_immutable_bytes(execution_root / entry["path"], payload)


def _evaluate_plan(
    execution_root: Path,
    fixtures_root: Path,
    plan: Mapping[str, Any],
    lock_manifest: Mapping[str, Any],
    settings: Mapping[str, Any],
    *,
    progress: Progress | None,
) -> dict[str, Any]:
    cases = {
        case.case_id: case
        for case in (load_case(path) for path in discover_cases(fixtures_root, "heldout"))
    }
    lock_digest = canonical_sha256(lock_manifest)
    completed = 0
    response_ids: set[str] = set()
    for evaluation in plan["evaluations"]:
        case = cases[evaluation["case_id"]]
        capture: dict[str, Any] | None = None
        semantic: dict[str, Any] | None = None
        if evaluation["invocation_id"] is not None:
            capture = _load_json(execution_root / evaluation["capture_path"], "model capture")
            response_id = capture.get("response_id")
            if not isinstance(response_id, str) or not response_id or response_id in response_ids:
                raise FalsificationError("model response identifiers must be unique")
            response_ids.add(response_id)
            semantic = _semantic_response(capture)
        started = _utc_now()
        packet = _compile_semantic(
            case,
            evaluation["arm"],
            semantic,
            allow_heldout=True,
        )
        completed_at = _utc_now()
        if capture is not None:
            started = capture["started_at"]
            completed_at = capture["completed_at"]
        raw = _raw_result(
            case_id=case.case_id,
            arm=evaluation["arm"],
            run_id=evaluation["run_id"],
            packet=packet,
            lock_digest=lock_digest,
            settings=settings if capture is not None else None,
            capture=capture,
            started_at=started,
            completed_at=completed_at,
        )
        result_path = execution_root / evaluation["result_path"]
        persist_raw_result(result_path, raw)
        os.chmod(result_path, 0o400)
        if capture is not None:
            request_bytes = (execution_root / evaluation["request_path"]).read_bytes()
            raw_response_bytes = (execution_root / evaluation["raw_response_path"]).read_bytes()
            capture_bytes = (execution_root / evaluation["capture_path"]).read_bytes()
            result_bytes = result_path.read_bytes()
            chain = build_digest_chain_record(
                evaluation,
                request_bytes=request_bytes,
                raw_response_bytes=raw_response_bytes,
                capture_bytes=capture_bytes,
                result_bytes=result_bytes,
            )
            write_immutable_json(execution_root / evaluation["chain_path"], chain)
        completed += 1
        _notify(progress, "evaluation", completed, len(plan["evaluations"]))

    recovery = run_recovery_matrix(
        fixtures_root,
        protocol_lock_digest=lock_digest,
        repeat=20,
    )
    by_identity = {
        (state, envelope["run_id"]): envelope
        for state, state_value in recovery["states"].items()
        for envelope in state_value["runs"]
    }
    for entry in plan["recovery"]:
        envelope = by_identity[(entry["state"], entry["run_id"])]
        write_immutable_json(execution_root / entry["result_path"], envelope)
    return _rebuild_recovery_bundle(fixtures_root, execution_root, plan, lock_digest)


def _rebuild_recovery_bundle(
    fixtures_root: Path,
    execution_root: Path,
    plan: Mapping[str, Any],
    lock_digest: str,
) -> dict[str, Any]:
    inputs = load_recovery_matrix_inputs(fixtures_root)
    states: dict[str, Any] = {}
    for state, metadata in inputs["states"].items():
        entries = [entry for entry in plan["recovery"] if entry["state"] == state]
        states[state] = {
            "fixture_digest": metadata["fixture_digest"],
            "expected_signature": deepcopy(metadata["expected_signature"]),
            "runs": [
                _load_json(execution_root / entry["result_path"], "recovery result")
                for entry in entries
            ],
        }
    return {
        "schema_version": "lazarus.recovery-repeatability/v1",
        "protocol_lock_digest": lock_digest,
        "matrix_sha256": inputs["matrix_sha256"],
        "repeat": 20,
        "states": states,
    }


def _score_execution(
    fixtures_root: Path,
    execution_root: Path,
    plan: Mapping[str, Any],
    lock_manifest: Mapping[str, Any],
    settings: Mapping[str, Any],
    recovery: Mapping[str, Any],
    repository: Path,
    oracles: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    evaluations = plan["evaluations"]
    paths = lambda arm: [
        execution_root / entry["result_path"]
        for entry in evaluations
        if entry["arm"] == arm
    ]
    return score_persisted_results(
        fixtures_root,
        lock_manifest=lock_manifest,
        a1_results=paths("a1"),
        a1_rules_results=paths("a1-rules"),
        b_results=paths("b-replay"),
        ablation_results={arm: paths(arm) for arm in ABLATION_ARMS},
        model_settings=settings,
        recovery_repeatability=recovery,
        repository_root=repository,
        execution_root=execution_root,
        oracle_mapping=oracles,
    )


def _verify_final_lock(
    lock_manifest: Mapping[str, Any],
    repository: Path,
    execution_root: Path,
    settings: Mapping[str, Any],
    plan: Mapping[str, Any],
    calibration_index: Mapping[str, Any],
    suite_manifest: Mapping[str, Any],
    suite_attestation: Mapping[str, Any],
    sealed_digest: str,
) -> None:
    verify_lock_manifest(
        lock_manifest,
        repository,
        execution_root=execution_root,
        model_settings=settings,
        execution_plan=plan,
        calibration_index=calibration_index,
        suite_manifest=suite_manifest,
        suite_attestation=suite_attestation,
        sealed_oracle_digest=sealed_digest,
    )


def _compile_semantic(
    case: BenchmarkCase,
    arm: str,
    semantic: Mapping[str, Any] | None,
    *,
    allow_heldout: bool,
) -> dict[str, Any]:
    try:
        return compile_case(
            case.directory,
            arm,
            semantic=semantic,
            allow_heldout=allow_heldout,
        )
    except ProtocolValidationError as exc:
        if not arm.startswith("b") or exc.contract not in {
            "semantic proposal envelope",
            "semantic proposal",
        }:
            raise
        return compile_case(
            case.directory,
            arm,
            semantic=None,
            allow_heldout=allow_heldout,
        )


def _semantic_response(capture: Mapping[str, Any]) -> dict[str, Any] | None:
    try:
        parsed = json.loads(
            capture["response_text"],
            object_pairs_hook=_unique_mapping,
        )
    except (KeyError, TypeError, UnicodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _raw_result(
    *,
    case_id: str,
    arm: str,
    run_id: str,
    packet: Mapping[str, Any],
    lock_digest: str,
    settings: Mapping[str, Any] | None,
    capture: Mapping[str, Any] | None,
    started_at: str | None = None,
    completed_at: str | None = None,
) -> dict[str, Any]:
    if capture is not None:
        started_at = str(capture["started_at"])
        completed_at = str(capture["completed_at"])
    raw: dict[str, Any] = {
        "schema_version": "lazarus.raw-result/v1",
        "case_id": case_id,
        "arm": arm,
        "run_id": run_id,
        "started_at": started_at or _utc_now(),
        "completed_at": completed_at or _utc_now(),
        "protocol_lock_digest": lock_digest,
        "output": {"packet": deepcopy(dict(packet))},
    }
    if capture is not None and settings is not None:
        raw["model_settings"] = deepcopy(dict(settings))
        raw["model_settings_digest"] = canonical_sha256(settings)
        raw["output"]["capture"] = deepcopy(dict(capture))
    return raw


def _summary(
    repository: Path,
    settings: Mapping[str, Any],
    *,
    generation_calls: int,
    calibration: Mapping[str, Any],
    lock_manifest: Mapping[str, Any] | None,
    score: Mapping[str, Any] | None,
    disposition: str,
) -> dict[str, Any]:
    repository_state = _git_state(repository)
    return {
        "schema_version": RUN_SUMMARY_SCHEMA_VERSION,
        "repository": repository_state,
        "model_settings": deepcopy(dict(settings)),
        "model_settings_sha256": canonical_sha256(settings),
        "generation_calls": generation_calls,
        "calibration_index_sha256": canonical_sha256(calibration),
        "lock_sha256": canonical_sha256(lock_manifest) if lock_manifest is not None else None,
        "score_sha256": canonical_sha256(score) if score is not None else None,
        "metrics": deepcopy(dict(score)) if score is not None else None,
        "disposition": disposition,
    }


def _bound(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(dict(value))
    return {
        "algorithm": "sha256",
        "digest": canonical_sha256(normalized),
        "value": normalized,
    }


def _evaluator_paths(repository: Path) -> tuple[Path, ...]:
    paths = tuple(sorted(path for path in (repository / "lazarus").glob("*.py") if path.is_file()))
    return (*paths, repository / "pyproject.toml")


def _verify_repository(repository: Path, *, require_exact_main: bool) -> None:
    state = _git_state(repository)
    if not state["tracked_clean"]:
        raise FalsificationError("repository has tracked changes")
    if not require_exact_main:
        return
    branch = _git(repository, "branch", "--show-current")
    remote = _git(repository, "rev-parse", "--verify", "origin/main")
    if branch != "main" or state["head_sha"] != remote:
        raise FalsificationError("registered run requires exact origin/main")


def _git_state(repository: Path) -> dict[str, Any]:
    head = _git(repository, "rev-parse", "--verify", "HEAD")
    tree = _git(repository, "rev-parse", "HEAD^{tree}")
    clean = not bool(_git(repository, "status", "--porcelain", "--untracked-files=no"))
    return {"head_sha": head, "tree_sha": tree, "tracked_clean": clean}


def _git(repository: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        raise FalsificationError("cannot inspect repository state") from exc
    return completed.stdout.strip()


def read_api_key(path: str | os.PathLike[str]) -> str:
    source = Path(path)
    try:
        metadata = source.lstat()
        if not stat.S_ISREG(metadata.st_mode) or source.is_symlink():
            raise FalsificationError("API key path must be a regular non-symlink file")
        if metadata.st_size < 8 or metadata.st_size > 4096:
            raise FalsificationError("API key file size is invalid")
        value = source.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise FalsificationError("cannot read API key file") from exc
    if not value or any(character.isspace() for character in value):
        raise FalsificationError("API key file must contain one non-empty token")
    return value


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_mapping,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise FalsificationError(f"cannot load {label}") from exc
    if not isinstance(value, dict):
        raise FalsificationError(f"{label} must be an object")
    return value


def _unique_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _notify(progress: Progress | None, stage: str, completed: int, total: int) -> None:
    if progress is not None:
        progress(stage, completed, total)


__all__ = [
    "CALIBRATION_CASE_IDS",
    "CALIBRATION_INDEX_SCHEMA_VERSION",
    "EXPECTED_GENERATION_CALLS",
    "FalsificationError",
    "FalsificationOutcome",
    "build_registered_model_settings",
    "read_api_key",
    "run_registered_falsification",
]
