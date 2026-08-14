"""Safe, deterministic identity for executable durable-runtime compatibility."""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import platform
import re
import sys
import tomllib
from dataclasses import asdict, dataclass
from importlib import metadata
from pathlib import Path
from types import CodeType, FunctionType
from typing import Any

from reconcile.persistence.durable import (
    COST_LEDGER_ENTRY_VERSION,
    COST_LEDGER_SNAPSHOT_VERSION,
    DURABLE_LEASE_VERSION,
    DURABLE_RUN_VERSION,
    PROBE_CHECKPOINT_VERSION,
    PROBE_RESUME_PLAN_VERSION,
    RUNTIME_TELEMETRY_VERSION,
)

RUNTIME_PROVENANCE_VERSION = "reconcile/runtime-provenance/v1"

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_REQUIREMENT_NAME_PATTERN = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_NORMALIZED_NAME_PATTERN = re.compile(r"[-_.]+")


class RuntimeProvenanceError(ValueError):
    """A required executable identity could not be resolved safely."""


@dataclass(frozen=True, slots=True)
class RuntimeProvenance:
    """Path- and secret-free executable identity suitable for durable binding."""

    schema_version: str
    source_manifest_sha256: str
    dependency_identity_sha256: str
    python_runtime_sha256: str
    runtime_schema_sha256: str
    executor_implementation_sha256: str
    cleanup_implementation_sha256: str
    strategy: str
    max_provider_calls: int
    max_estimated_cost_microunits: int
    semantic_config_sha256: str
    sha256: str


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_sha256(path: Path, *, failure: str) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            raise RuntimeProvenanceError(failure)
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except RuntimeProvenanceError:
        raise
    except OSError as error:
        raise RuntimeProvenanceError(failure) from error


def _source_manifest_sha256(package_root: Path) -> str:
    try:
        root = package_root.resolve(strict=True)
        if package_root.is_symlink() or not root.is_dir():
            raise RuntimeProvenanceError("RECONCILE source manifest cannot be resolved")
        candidates = sorted(root.rglob("*.py"), key=lambda item: item.as_posix())
    except RuntimeProvenanceError:
        raise
    except OSError as error:
        raise RuntimeProvenanceError(
            "RECONCILE source manifest cannot be resolved"
        ) from error
    if not candidates:
        raise RuntimeProvenanceError("RECONCILE source manifest is empty")

    manifest: list[dict[str, str]] = []
    for candidate in candidates:
        try:
            relative = candidate.relative_to(root).as_posix()
        except ValueError as error:
            raise RuntimeProvenanceError(
                "RECONCILE source manifest escaped its package root"
            ) from error
        manifest.append(
            {
                "name": relative,
                "sha256": _file_sha256(
                    candidate,
                    failure="RECONCILE source file cannot be resolved",
                ),
            }
        )
    return _sha256(manifest)


def _normalized_distribution_name(value: str) -> str:
    return _NORMALIZED_NAME_PATTERN.sub("-", value).lower()


def _declared_requirements_from_project(
    project_root: Path,
) -> tuple[list[str], str, str]:
    pyproject = project_root / "pyproject.toml"
    pyproject_sha256 = _file_sha256(
        pyproject,
        failure="declared dependency metadata cannot be resolved",
    )
    try:
        document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        project = document["project"]
        requirements = project["dependencies"]
    except (
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise RuntimeProvenanceError(
            "declared dependency metadata cannot be resolved"
        ) from error
    if not isinstance(requirements, list) or any(
        not isinstance(item, str) or not item.strip() for item in requirements
    ):
        raise RuntimeProvenanceError("declared dependency metadata cannot be resolved")

    lock = project_root / "uv.lock"
    lock_sha256 = (
        _file_sha256(lock, failure="dependency lock identity cannot be resolved")
        if lock.exists() or lock.is_symlink()
        else _sha256({"lock": "absent"})
    )
    return requirements, pyproject_sha256, lock_sha256


def _declared_requirements_from_distribution() -> tuple[list[str], str, str]:
    try:
        requirements = metadata.requires("reconcile")
        project_version = metadata.version("reconcile")
    except metadata.PackageNotFoundError as error:
        raise RuntimeProvenanceError(
            "installed declared dependencies cannot be resolved"
        ) from error
    if requirements is None or any(
        not isinstance(item, str) or not item.strip() for item in requirements
    ):
        raise RuntimeProvenanceError(
            "installed declared dependencies cannot be resolved"
        )
    distribution_identity = _sha256(
        {
            "name": "reconcile",
            "requirements": sorted(requirements),
            "version": project_version,
        }
    )
    return requirements, distribution_identity, _sha256({"lock": "unavailable"})


def _dependency_identity_sha256(
    project_root: Path,
    *,
    require_project_metadata: bool,
) -> str:
    if (project_root / "pyproject.toml").exists() or require_project_metadata:
        requirements, declaration_sha256, lock_sha256 = (
            _declared_requirements_from_project(project_root)
        )
    else:
        requirements, declaration_sha256, lock_sha256 = (
            _declared_requirements_from_distribution()
        )

    installed: list[dict[str, str]] = []
    seen: set[str] = set()
    for requirement in requirements:
        match = _REQUIREMENT_NAME_PATTERN.match(requirement)
        if match is None:
            raise RuntimeProvenanceError("declared dependency name cannot be resolved")
        name = _normalized_distribution_name(match.group(1))
        if name in seen:
            raise RuntimeProvenanceError("declared dependency identity is ambiguous")
        seen.add(name)
        try:
            version = metadata.version(name)
        except metadata.PackageNotFoundError as error:
            raise RuntimeProvenanceError(
                "installed declared dependency version cannot be resolved"
            ) from error
        if not isinstance(version, str) or not version:
            raise RuntimeProvenanceError(
                "installed declared dependency version cannot be resolved"
            )
        installed.append(
            {
                "declared_requirement_sha256": hashlib.sha256(
                    requirement.encode("utf-8")
                ).hexdigest(),
                "name": name,
                "version": version,
            }
        )
    return _sha256(
        {
            "declaration_sha256": declaration_sha256,
            "installed": sorted(installed, key=lambda item: item["name"]),
            "lock_sha256": lock_sha256,
        }
    )


def _constant_identity(value: object) -> object:
    if value is None or value is Ellipsis:
        return {"type": type(value).__name__}
    if isinstance(value, bool):
        return {"bool": value}
    if isinstance(value, int):
        return {"int": str(value)}
    if isinstance(value, float):
        return {"float": value.hex()}
    if isinstance(value, complex):
        return {"complex": [value.real.hex(), value.imag.hex()]}
    if isinstance(value, str):
        return {
            "str_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        }
    if isinstance(value, bytes):
        return {"bytes_sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, tuple):
        return {"tuple": [_constant_identity(item) for item in value]}
    if isinstance(value, frozenset):
        members = [_constant_identity(item) for item in value]
        return {"frozenset": sorted(members, key=_canonical_bytes)}
    if isinstance(value, CodeType):
        return {"code": _code_identity(value)}
    raise RuntimeProvenanceError("callable implementation constant is unsupported")


def _code_identity(code: CodeType) -> dict[str, object]:
    return {
        "argcount": code.co_argcount,
        "cellvars": list(code.co_cellvars),
        "code_sha256": hashlib.sha256(code.co_code).hexdigest(),
        "consts": [_constant_identity(item) for item in code.co_consts],
        "exceptiontable_sha256": hashlib.sha256(code.co_exceptiontable).hexdigest(),
        "flags": code.co_flags,
        "freevars": list(code.co_freevars),
        "kwonlyargcount": code.co_kwonlyargcount,
        "name": code.co_name,
        "names": list(code.co_names),
        "nlocals": code.co_nlocals,
        "posonlyargcount": code.co_posonlyargcount,
        "qualname": code.co_qualname,
        "stacksize": code.co_stacksize,
        "varnames": list(code.co_varnames),
    }


def _function_identity(function: FunctionType) -> dict[str, object]:
    try:
        unwrapped = inspect.unwrap(function)
    except ValueError as error:
        raise RuntimeProvenanceError(
            "callable implementation cannot be unwrapped"
        ) from error
    if not isinstance(unwrapped, FunctionType):
        raise RuntimeProvenanceError("callable implementation code cannot be resolved")
    closure = unwrapped.__closure__
    closure_identity: list[object] = []
    if closure is not None:
        for cell in closure:
            try:
                closure_identity.append(_constant_identity(cell.cell_contents))
            except ValueError as error:
                raise RuntimeProvenanceError(
                    "callable closure identity cannot be resolved"
                ) from error
    return {
        "closure": closure_identity,
        "code": _code_identity(unwrapped.__code__),
        "defaults": _constant_identity(unwrapped.__defaults__),
        "kwdefaults": _constant_identity(
            tuple(sorted((unwrapped.__kwdefaults__ or {}).items()))
        ),
        "module": unwrapped.__module__,
        "qualname": unwrapped.__qualname__,
    }


def _callable_implementation_sha256(value: object, *, role: str) -> str:
    if isinstance(value, functools.partial):
        identity: dict[str, Any] = {
            "args": _constant_identity(value.args),
            "function": _callable_identity(value.func),
            "keywords": _constant_identity(
                tuple(sorted((value.keywords or {}).items()))
            ),
            "kind": "partial",
        }
    else:
        identity = _callable_identity(value)
    try:
        return _sha256({"identity": identity, "role": role})
    except (TypeError, ValueError) as error:
        raise RuntimeProvenanceError(
            f"{role} implementation identity cannot be resolved"
        ) from error


def _callable_identity(value: object) -> dict[str, object]:
    if inspect.ismethod(value):
        function = value.__func__
        owner = type(value.__self__)
    elif inspect.isfunction(value):
        function = value
        owner = None
    else:
        if not callable(value):
            raise RuntimeProvenanceError("callable implementation is required")
        owner = type(value)
        function = inspect.getattr_static(owner, "__call__", None)
        if isinstance(function, staticmethod | classmethod):
            function = function.__func__
    if not isinstance(function, FunctionType):
        raise RuntimeProvenanceError("callable implementation code cannot be resolved")
    return {
        "function": _function_identity(function),
        "kind": "function" if owner is None else "instance",
        "owner_module": None if owner is None else owner.__module__,
        "owner_qualname": None if owner is None else owner.__qualname__,
    }


def _python_runtime_sha256() -> str:
    return _sha256(
        {
            "abiflags": sys.abiflags,
            "byteorder": sys.byteorder,
            "cache_tag": sys.implementation.cache_tag,
            "implementation": platform.python_implementation(),
            "implementation_name": sys.implementation.name,
            "version": list(sys.version_info[:5]),
        }
    )


def _runtime_schema_sha256() -> str:
    return _sha256(
        {
            "cost_ledger_entry": COST_LEDGER_ENTRY_VERSION,
            "cost_ledger_snapshot": COST_LEDGER_SNAPSHOT_VERSION,
            "durable_lease": DURABLE_LEASE_VERSION,
            "durable_run": DURABLE_RUN_VERSION,
            "probe_checkpoint": PROBE_CHECKPOINT_VERSION,
            "probe_resume_plan": PROBE_RESUME_PLAN_VERSION,
            "runtime_telemetry": RUNTIME_TELEMETRY_VERSION,
        }
    )


def build_runtime_provenance(
    *,
    executor: object,
    cleanup: object | None,
    strategy: str,
    max_provider_calls: int,
    max_estimated_cost_microunits: int,
    semantic_config_sha256: str,
    package_root: Path | None = None,
    project_root: Path | None = None,
) -> RuntimeProvenance:
    """Resolve a canonical executable identity without retaining sensitive inputs."""

    if type(strategy) is not str or not strategy:
        raise RuntimeProvenanceError("runtime strategy identity is required")
    if (
        type(max_provider_calls) is not int
        or max_provider_calls < 0
        or type(max_estimated_cost_microunits) is not int
        or max_estimated_cost_microunits < 0
    ):
        raise RuntimeProvenanceError(
            "runtime provider limits must be nonnegative integers"
        )
    if (
        type(semantic_config_sha256) is not str
        or _SHA256_PATTERN.fullmatch(semantic_config_sha256) is None
    ):
        raise RuntimeProvenanceError(
            "semantic configuration attestation must be a SHA-256 digest"
        )

    explicit_project_root = project_root is not None
    resolved_package_root = (
        Path(__file__).resolve().parent if package_root is None else Path(package_root)
    )
    resolved_project_root = (
        resolved_package_root.parent if project_root is None else Path(project_root)
    )
    cleanup_identity = (
        _sha256({"cleanup": "absent"})
        if cleanup is None
        else _callable_implementation_sha256(cleanup, role="cleanup")
    )
    material = {
        "schema_version": RUNTIME_PROVENANCE_VERSION,
        "source_manifest_sha256": _source_manifest_sha256(resolved_package_root),
        "dependency_identity_sha256": _dependency_identity_sha256(
            resolved_project_root,
            require_project_metadata=explicit_project_root,
        ),
        "python_runtime_sha256": _python_runtime_sha256(),
        "runtime_schema_sha256": _runtime_schema_sha256(),
        "executor_implementation_sha256": _callable_implementation_sha256(
            executor,
            role="executor",
        ),
        "cleanup_implementation_sha256": cleanup_identity,
        "strategy": strategy,
        "max_provider_calls": max_provider_calls,
        "max_estimated_cost_microunits": max_estimated_cost_microunits,
        "semantic_config_sha256": semantic_config_sha256,
    }
    return RuntimeProvenance(**material, sha256=_sha256(material))


def runtime_provenance_material(identity: RuntimeProvenance) -> bytes:
    """Return canonical safe material for audit/testing without raw inputs."""

    if type(identity) is not RuntimeProvenance:
        raise TypeError("runtime provenance identity must be exact")
    return _canonical_bytes(asdict(identity))


__all__ = [
    "RUNTIME_PROVENANCE_VERSION",
    "RuntimeProvenance",
    "RuntimeProvenanceError",
    "build_runtime_provenance",
    "runtime_provenance_material",
]
