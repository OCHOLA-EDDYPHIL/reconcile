from __future__ import annotations

import argparse
from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from lazarus.benchmark import (
    BenchmarkError,
    build_model_input,
    discover_cases,
    freeze_benchmark,
    load_case as load_benchmark_case,
    persist_raw_result,
    score_persisted_results,
    validate_model_capture,
    validate_suite,
    verify_benchmark_lock,
)
from lazarus.compiler import ARMS, B_ARMS, CompilationError, compile_case, load_case
from lazarus.locking import LockingError, canonical_json_bytes, canonical_sha256
from lazarus.protocol import ProtocolValidationError, validate_case_contract
from lazarus.recovery import RecoveryMatrixError, run_recovery, run_recovery_matrix


class CommandError(ValueError):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lazarus")
    subcommands = parser.add_subparsers(dest="command", required=True)

    validate = subcommands.add_parser("validate", help="validate a case or fixture suite")
    validate.add_argument("path", type=Path)
    validate.add_argument("--suite", action="store_true")

    compile_command = subcommands.add_parser("compile", help="compile one evidence packet")
    compile_command.add_argument("case", type=Path)
    compile_command.add_argument("--arm", choices=ARMS, required=True)
    compile_command.add_argument("--semantic-response", type=Path)
    compile_command.add_argument("--without-recovery", action="store_true")
    compile_command.add_argument("--output", type=Path)

    restore = subcommands.add_parser("restore", help="run deterministic recovery checks")
    restore.add_argument("case", type=Path)
    restore.add_argument("--repeat", type=_positive_integer, default=1)
    restore.add_argument("--output", type=Path)

    repeatability = subcommands.add_parser(
        "repeatability", help="run the locked six-state recovery matrix"
    )
    repeatability.add_argument("fixtures", type=Path)
    repeatability.add_argument("--lock", type=Path, required=True)
    repeatability.add_argument("--model-settings", type=Path, required=True)
    repeatability.add_argument("--repository-root", type=Path, default=Path.cwd())
    repeatability.add_argument("--output", type=Path, required=True)

    render = subcommands.add_parser("render-input", help="render one bounded model input")
    render.add_argument("fixtures", type=Path)
    render.add_argument("case", type=Path)
    render.add_argument("--arm", choices=B_ARMS, required=True)
    render.add_argument("--lock", type=Path)
    render.add_argument("--model-settings", type=Path)
    render.add_argument("--repository-root", type=Path, default=Path.cwd())
    render.add_argument("--output", type=Path)

    freeze = subcommands.add_parser("freeze", help="create a complete protocol lock")
    freeze.add_argument("fixtures", type=Path)
    freeze.add_argument("--model-settings", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    freeze.add_argument("--repository-root", type=Path, default=Path.cwd())

    verify = subcommands.add_parser("verify", help="verify a protocol lock")
    verify.add_argument("lock", type=Path)
    verify.add_argument("fixtures", type=Path)
    verify.add_argument("--model-settings", type=Path)
    verify.add_argument("--repository-root", type=Path, default=Path.cwd())

    evaluate = subcommands.add_parser("evaluate", help="compile and persist raw arm outputs")
    evaluate.add_argument("fixtures", type=Path)
    evaluate.add_argument("--split", choices=("calibration", "heldout"), required=True)
    evaluate.add_argument("--arm", choices=ARMS, required=True)
    evaluate.add_argument("--run-id", required=True)
    evaluate.add_argument("--output-dir", type=Path, required=True)
    evaluate.add_argument("--semantic-dir", type=Path)
    evaluate.add_argument("--lock", type=Path)
    evaluate.add_argument("--model-settings", type=Path)
    evaluate.add_argument("--repository-root", type=Path, default=Path.cwd())

    score = subcommands.add_parser("score", help="score persisted held-out results")
    score.add_argument("fixtures", type=Path)
    score.add_argument("--lock", type=Path, required=True)
    score.add_argument("--model-settings", type=Path, required=True)
    score.add_argument("--a1-result", action="append", type=Path, required=True)
    score.add_argument("--a1-rules-result", action="append", type=Path, required=True)
    score.add_argument("--b-result", action="append", type=Path, required=True)
    score.add_argument("--b-no-alias-result", action="append", type=Path, required=True)
    score.add_argument("--b-no-intent-result", action="append", type=Path, required=True)
    score.add_argument("--b-no-probe-result", action="append", type=Path, required=True)
    score.add_argument("--b-no-incident-result", action="append", type=Path, required=True)
    score.add_argument("--recovery-repeatability", type=Path, required=True)
    score.add_argument("--repository-root", type=Path, default=Path.cwd())
    score.add_argument("--output", type=Path)

    falsify = subcommands.add_parser(
        "falsify", help="run the registered Gemini falsification protocol"
    )
    falsify.add_argument("--api-key-file", type=Path, required=True)
    falsify.add_argument("--run-root", type=Path, required=True)
    falsify.add_argument("--repository-root", type=Path, default=Path.cwd())
    return parser


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_mapping,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise CommandError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CommandError(f"{path} must contain a JSON object")
    return value


def _unique_json_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _semantic_response(capture: Mapping[str, Any]) -> dict[str, Any] | None:
    try:
        value = json.loads(
            capture["response_text"],
            object_pairs_hook=_unique_json_mapping,
        )
    except (KeyError, TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _emit(value: Any, destination: Path | None = None) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    if destination is None:
        sys.stdout.buffer.write(payload)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("xb") as stream:
            stream.write(payload)
    except FileExistsError as exc:
        raise CommandError(f"refusing to overwrite {destination}") from exc


def _emit_bytes(payload: bytes, destination: Path | None = None) -> None:
    if destination is None:
        sys.stdout.buffer.write(payload)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("xb") as stream:
            stream.write(payload)
    except FileExistsError as exc:
        raise CommandError(f"refusing to overwrite {destination}") from exc


def _validate_command(arguments: argparse.Namespace) -> dict[str, Any]:
    if arguments.suite:
        return {"schema_version": "lazarus.validation/v1", "suite": validate_suite(arguments.path)}
    case, _artifacts = load_case(arguments.path)
    validate_case_contract(case)
    benchmark_case = load_benchmark_case(arguments.path)
    return {
        "schema_version": "lazarus.validation/v1",
        "case_id": benchmark_case.case_id,
        "split": benchmark_case.split,
        "artifact_count": len(benchmark_case.artifacts),
    }


def _compile_command(arguments: argparse.Namespace) -> dict[str, Any]:
    case, _artifacts = load_case(arguments.case)
    if case["split"] == "heldout":
        raise CommandError("direct compile is disabled for heldout cases; use locked evaluate")
    semantic = _load_json(arguments.semantic_response) if arguments.semantic_response else None
    if arguments.arm not in B_ARMS and semantic is not None:
        raise CommandError("semantic responses are accepted only by B replay arms")
    return compile_case(
        arguments.case,
        arguments.arm,
        semantic=semantic,
        include_recovery=not arguments.without_recovery,
    )


def _restore_command(arguments: argparse.Namespace) -> dict[str, Any]:
    case, _artifacts = load_case(arguments.case)
    if case["split"] == "heldout":
        raise CommandError("direct restore is disabled for heldout cases; use locked evaluate")
    validated = validate_case_contract(case)
    results = [run_recovery(arguments.case, validated["recovery"]) for _ in range(arguments.repeat)]
    signatures = [
        {
            "classification": result["classification"],
            "restore": result["restore"]["status"],
            "canary": result["canary"]["status"],
            "rpo": result["rpo"]["status"],
            "rto": result["rto"]["status"],
            "cleanup": result["cleanup"]["status"],
        }
        for result in results
    ]
    return {
        "schema_version": "lazarus.recovery-case-run/v1",
        "case_id": validated["case_id"],
        "runs": arguments.repeat,
        "identical": sum(signature == signatures[0] for signature in signatures),
        "passed": len(set(json.dumps(signature, sort_keys=True) for signature in signatures)) == 1,
        "signature": signatures[0],
        "results": results,
    }


def _render_input_command(arguments: argparse.Namespace) -> bytes:
    case = load_benchmark_case(arguments.case)
    registered = {
        path.resolve() for path in discover_cases(arguments.fixtures, case.split)
    }
    if case.directory.resolve() not in registered:
        raise CommandError("case is not registered in the supplied fixture suite")
    if case.split == "heldout":
        if arguments.lock is None or arguments.model_settings is None:
            raise CommandError("heldout model input requires a verified lock and exact settings")
        verify_benchmark_lock(
            arguments.lock,
            arguments.fixtures,
            repository_root=arguments.repository_root,
            model_settings=_load_json(arguments.model_settings),
        )
    return build_model_input(
        case,
        arguments.arm,
        arguments.fixtures / "protocol" / "prompts",
    )


def _repeatability_command(arguments: argparse.Namespace) -> dict[str, Any]:
    model_settings = _load_json(arguments.model_settings)
    verify_benchmark_lock(
        arguments.lock,
        arguments.fixtures,
        repository_root=arguments.repository_root,
        model_settings=model_settings,
    )
    lock_digest = canonical_sha256(_load_json(arguments.lock))
    return run_recovery_matrix(
        arguments.fixtures,
        protocol_lock_digest=lock_digest,
    )


def _evaluate_command(arguments: argparse.Namespace) -> dict[str, Any]:
    model_settings = _load_json(arguments.model_settings) if arguments.model_settings else None
    lock_digest: str | None = None
    if arguments.split == "heldout":
        if arguments.lock is None or model_settings is None:
            raise CommandError("heldout evaluation requires a lock and exact model settings")
        verify_benchmark_lock(
            arguments.lock,
            arguments.fixtures,
            repository_root=arguments.repository_root,
            model_settings=model_settings,
        )
        lock_digest = canonical_sha256(_load_json(arguments.lock))
    if arguments.arm in B_ARMS and arguments.semantic_dir is None:
        raise CommandError("B replay evaluation requires model captures")
    if arguments.arm in B_ARMS and model_settings is None:
        raise CommandError("B replay evaluation requires exact model settings")
    if arguments.arm not in B_ARMS and arguments.semantic_dir is not None:
        raise CommandError("model capture directories are accepted only by B replay arms")

    paths: list[str] = []
    for case_path in discover_cases(arguments.fixtures, arguments.split):
        case = load_benchmark_case(case_path)
        semantic: dict[str, Any] | None = None
        capture: dict[str, Any] | None = None
        if arguments.semantic_dir is not None:
            capture = validate_model_capture(
                _load_json(arguments.semantic_dir / f"{case.case_id}.json"),
                model_settings=model_settings,
                arm=arguments.arm,
            )
            expected_prompt_digest = hashlib.sha256(
                build_model_input(
                    case,
                    arguments.arm,
                    arguments.fixtures / "protocol" / "prompts",
                )
            ).hexdigest()
            if capture["prompt_sha256"] != expected_prompt_digest:
                raise CommandError(
                    f"model capture for {case.case_id} does not match its assembled input"
                )
            semantic = _semantic_response(capture)
        started = datetime.now(timezone.utc)
        try:
            packet = compile_case(
                case.directory,
                arguments.arm,
                semantic=semantic,
                allow_heldout=arguments.split == "heldout",
            )
        except ProtocolValidationError as exc:
            if arguments.arm not in B_ARMS or exc.contract not in {
                "semantic proposal envelope",
                "semantic proposal",
            }:
                raise
            packet = compile_case(
                case.directory,
                arguments.arm,
                semantic=None,
                allow_heldout=arguments.split == "heldout",
            )
        completed = datetime.now(timezone.utc)
        if capture is not None:
            started_text = capture["started_at"]
            completed_text = capture["completed_at"]
            output: dict[str, Any] = {"packet": packet, "capture": capture}
        else:
            started_text = started.isoformat().replace("+00:00", "Z")
            completed_text = completed.isoformat().replace("+00:00", "Z")
            output = {"packet": packet}
        raw: dict[str, Any] = {
            "schema_version": "lazarus.raw-result/v1",
            "case_id": case.case_id,
            "arm": arguments.arm,
            "run_id": arguments.run_id,
            "started_at": started_text,
            "completed_at": completed_text,
            "output": output,
        }
        if lock_digest is not None:
            raw["protocol_lock_digest"] = lock_digest
        if arguments.arm in B_ARMS:
            raw["model_settings"] = model_settings
            raw["model_settings_digest"] = canonical_sha256(model_settings)
        persisted = persist_raw_result(arguments.output_dir, raw)
        paths.append(str(persisted))
    return {
        "schema_version": "lazarus.evaluation-index/v1",
        "split": arguments.split,
        "arm": arguments.arm,
        "run_id": arguments.run_id,
        "results": paths,
    }


def _result_files(paths: list[Path]) -> list[Path]:
    results: list[Path] = []
    for path in paths:
        if path.is_dir():
            results.extend(sorted(path.rglob("*.json")))
        elif path.is_file():
            results.append(path)
        else:
            raise CommandError(f"result path does not exist: {path}")
    return results


def _falsification_progress(stage: str, completed: int, total: int) -> None:
    if completed in {0, total} or total <= 4 or completed % 10 == 0:
        print(f"lazarus: {stage} {completed}/{total}", file=sys.stderr, flush=True)


def _run(arguments: argparse.Namespace) -> tuple[Any, Path | None]:
    if arguments.command == "validate":
        return _validate_command(arguments), None
    if arguments.command == "compile":
        return _compile_command(arguments), arguments.output
    if arguments.command == "restore":
        return _restore_command(arguments), arguments.output
    if arguments.command == "repeatability":
        return _repeatability_command(arguments), arguments.output
    if arguments.command == "render-input":
        return _render_input_command(arguments), arguments.output
    if arguments.command == "freeze":
        manifest = freeze_benchmark(
            arguments.fixtures,
            model_settings=_load_json(arguments.model_settings),
            destination=arguments.output,
            repository_root=arguments.repository_root,
        )
        return manifest, None
    if arguments.command == "verify":
        settings = _load_json(arguments.model_settings) if arguments.model_settings else None
        verify_benchmark_lock(
            arguments.lock,
            arguments.fixtures,
            repository_root=arguments.repository_root,
            model_settings=settings,
        )
        return {"schema_version": "lazarus.lock-verification/v1", "verified": True}, None
    if arguments.command == "evaluate":
        return _evaluate_command(arguments), None
    if arguments.command == "score":
        score = score_persisted_results(
            arguments.fixtures,
            lock_manifest=arguments.lock,
            a1_results=_result_files(arguments.a1_result),
            a1_rules_results=_result_files(arguments.a1_rules_result),
            b_results=_result_files(arguments.b_result),
            ablation_results={
                "b-replay-no-alias": _result_files(arguments.b_no_alias_result),
                "b-replay-no-intent": _result_files(arguments.b_no_intent_result),
                "b-replay-no-probe": _result_files(arguments.b_no_probe_result),
                "b-replay-no-incident": _result_files(arguments.b_no_incident_result),
            },
            model_settings=_load_json(arguments.model_settings),
            recovery_repeatability=_load_json(arguments.recovery_repeatability),
            repository_root=arguments.repository_root,
        )
        return score, arguments.output
    if arguments.command == "falsify":
        from lazarus.falsification import read_api_key, run_registered_falsification

        outcome = run_registered_falsification(
            arguments.repository_root,
            arguments.run_root,
            api_key=read_api_key(arguments.api_key_file),
            progress=_falsification_progress,
        )
        return outcome.summary, None
    raise CommandError(f"unsupported command: {arguments.command}")


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        value, output = _run(arguments)
        if arguments.command == "render-input":
            _emit_bytes(value, output)
        elif arguments.command != "freeze":
            _emit(value, output)
        else:
            _emit(
                {
                    "schema_version": value["schema_version"],
                    "lock_path": str(arguments.output),
                    "model_settings_digest": value["model_settings"]["digest"],
                }
            )
        return 0
    except (
        BenchmarkError,
        CommandError,
        CompilationError,
        LockingError,
        OSError,
        ProtocolValidationError,
        RecoveryMatrixError,
        ValueError,
    ) as exc:
        print(f"lazarus: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
