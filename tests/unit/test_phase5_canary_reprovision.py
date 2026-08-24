"""Focused safety tests for physical Phase 5 canary reprovisioning."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

import reconcile.phase5_hosted_acceptance as acceptance_module
from reconcile import phase5_operator as operator_module
from reconcile.phase5_hosted_acceptance import (
    CanaryReprovisionBinding,
    HostedAcceptanceError,
    TerraformCanaryReprovisioner,
    build_candidate_identity,
)

pytestmark = pytest.mark.unit

PROJECT = "reconcile-dev-260813-14fa6d"
SOURCE = "1" * 40
IMAGE = f"sha256:{'2' * 64}"
INFRASTRUCTURE = "3" * 64
SEMANTIC = "4" * 64
RELEASE = f"p5-release-{SOURCE[:24]}"
TERRAFORM_BYTES = b"pinned terraform fixture"


def test_phase5_command_runners_force_private_file_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(kwargs)
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", run)
    operator_module._default_runner(
        ("fixed",), cwd=tmp_path, environment={}, timeout_seconds=1
    )
    acceptance_module._default_command_runner(("fixed",), tmp_path, {}, 1)

    assert [call["umask"] for call in calls] == [0o077, 0o077]


class _ReleaseReader:
    def __init__(self, result: object | None = None) -> None:
        self.result = result
        self.calls: list[str] = []

    async def read(self, release_id: str) -> object | None:
        self.calls.append(release_id)
        return self.result


def _candidate():
    return build_candidate_identity(
        source_revision=SOURCE,
        image_digest=IMAGE,
        infrastructure_revision=INFRASTRUCTURE,
        semantic_config_sha256=SEMANTIC,
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _variables() -> dict[str, object]:
    return {
        "api_invoker_members": [
            f"serviceAccount:rec-p5-apply@{PROJECT}.iam.gserviceaccount.com"
        ],
        "image_digest": IMAGE,
        "infrastructure_revision": INFRASTRUCTURE,
        "project_id": PROJECT,
        "region": "us-central1",
        "request_timeout_seconds": {
            "api": 300,
            "canary": 60,
            "controller": 300,
            "fault_proxy": 60,
            "sandbox": 60,
        },
        "semantic_config_sha256": SEMANTIC,
        "service_account_emails": {
            "api": f"rec-p5-api@{PROJECT}.iam.gserviceaccount.com",
            "canary": f"rec-p5-canary@{PROJECT}.iam.gserviceaccount.com",
            "controller": f"rec-p5-controller@{PROJECT}.iam.gserviceaccount.com",
            "fault_proxy": f"rec-p5-fault@{PROJECT}.iam.gserviceaccount.com",
            "sandbox": f"rec-p5-sandbox@{PROJECT}.iam.gserviceaccount.com",
        },
        "source_revision": SOURCE,
        "vertex_location": "us",
        "vertex_model": "gemini-3.5-flash",
        "vertex_prompt_sha256": (
            "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"
        ),
        "vertex_prompt_version": "adaptive-planner-v3",
    }


def _write(path: Path, payload: bytes, mode: int) -> None:
    path.write_bytes(payload)
    path.chmod(mode)


def _state(tmp_path: Path) -> tuple[CanaryReprovisionBinding, dict[str, object]]:
    root = tmp_path / "operator-state"
    root.mkdir(mode=0o700)
    source = root / "source"
    runtime = source / "infra" / "environments" / "dev" / "runtime"
    runtime.mkdir(parents=True, mode=0o700)
    entries = []
    for index, name in enumerate(acceptance_module._RUNTIME_SOURCE_FILES, 1):
        payload = f"runtime source {index}\n".encode()
        _write(runtime / name, payload, 0o400)
        entries.append(
            {
                "path": f"infra/environments/dev/runtime/{name}",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    runtime.chmod(0o500)
    source.chmod(0o500)

    plans = root / "plans"
    plans.mkdir(mode=0o700)
    variables = _variables()
    variable_payload = _canonical(variables)
    _write(plans / "runtime-create.tfvars.json", variable_payload, 0o400)
    (root / "execution").mkdir(mode=0o700)
    data = root / "terraform-data" / "runtime"
    data.mkdir(parents=True, mode=0o700)
    _write(
        data / "terraform.tfstate",
        _canonical(
            {
                "backend": {
                    "config": {
                        "bucket": f"{PROJECT}-p5-state",
                        "impersonate_service_account": (
                            f"rec-p5-apply@{PROJECT}.iam.gserviceaccount.com"
                        ),
                        "prefix": "phase5/runtime",
                    },
                    "type": "gcs",
                },
                "version": 3,
            }
        ),
        0o600,
    )
    _write(root / "terraform.rc", b"", 0o400)
    return (
        CanaryReprovisionBinding(
            state_root=str(root),
            runtime_source_sha256=hashlib.sha256(_canonical(entries)).hexdigest(),
            runtime_variables_sha256=hashlib.sha256(variable_payload).hexdigest(),
        ),
        variables,
    )


def _service(uid: str, baseline: str) -> bytes:
    return _canonical(
        {
            "metadata": {
                "generation": 8,
                "name": "reconcile-p5-canary",
                "uid": uid,
            },
            "status": {
                "conditions": [{"status": "True", "type": "Ready"}],
                "latestCreatedRevisionName": baseline,
                "latestReadyRevisionName": baseline,
                "observedGeneration": 8,
                "traffic": [{"percent": 100, "revisionName": baseline}],
            },
        }
    )


def _revisions(baseline: str, *, residual: bool = False) -> bytes:
    revision = {
        "metadata": {
            "annotations": {"reconcile.dev/configuration-sha256": SEMANTIC},
            "generation": 1,
            "labels": {"reconcile-release": "baseline"},
            "name": baseline,
        },
        "spec": {
            "containers": [
                {
                    "image": (
                        f"us-central1-docker.pkg.dev/{PROJECT}/reconcile-p5/"
                        f"reconcile@{IMAGE}"
                    )
                }
            ]
        },
        "status": {
            "conditions": [{"status": "True", "type": "Ready"}],
            "observedGeneration": 1,
        },
    }
    values = [revision]
    if residual:
        values.append(
            {
                **revision,
                "metadata": {
                    **revision["metadata"],
                    "name": "reconcile-p5-canary-r-residue",
                },
            }
        )
    return _canonical(values)


def _replacement(address: str) -> dict[str, object]:
    projection: dict[str, object] = {
        "location": "us-central1",
        "name": "reconcile-p5-canary",
        "project": PROJECT,
    }
    if address in acceptance_module._CANARY_REPROVISION_IAM:
        role, member = acceptance_module._CANARY_REPROVISION_IAM[address]
        projection.update({"member": member, "role": role})
    before = json.loads(json.dumps(projection))
    if address in acceptance_module._CANARY_REPROVISION_IAM:
        before["name"] = (
            f"projects/{PROJECT}/locations/us-central1/services/reconcile-p5-canary"
        )
    return {
        "action_reason": "replace_by_request",
        "address": address,
        "change": {
            "actions": ["delete", "create"],
            "after": projection,
            "before": before,
        },
        "mode": "managed",
        "provider_name": "registry.terraform.io/hashicorp/google",
        "type": acceptance_module._CANARY_REPROVISION_TYPES[address],
    }


def _plan(
    variables: dict[str, object],
    *,
    extra_change: dict[str, object] | None = None,
    omit: str | None = None,
) -> bytes:
    changes = [
        _replacement(address)
        for address in acceptance_module._CANARY_REPROVISION_ADDRESSES
        if address != omit
    ]
    if extra_change is not None:
        changes.append(extra_change)
    return _canonical(
        {
            "format_version": "1.2",
            "resource_changes": changes,
            "resource_drift": [],
            "terraform_version": "1.15.8",
            "variables": {name: {"value": value} for name, value in variables.items()},
        }
    )


def _install_terraform(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    binary = tmp_path / "terraform"
    _write(binary, TERRAFORM_BYTES, 0o500)
    monkeypatch.setattr(acceptance_module, "_TERRAFORM", str(binary))
    monkeypatch.setattr(
        acceptance_module,
        "_TERRAFORM_SHA256",
        hashlib.sha256(TERRAFORM_BYTES).hexdigest(),
    )
    return binary


class _Runner:
    def __init__(
        self,
        *,
        baseline: str,
        plan: bytes,
        current_uid: str = "uid-new",
        residual_revision: bool = False,
    ) -> None:
        self.baseline = baseline
        self.plan = plan
        self.current_uid = current_uid
        self.residual_revision = residual_revision
        self.calls: list[tuple[tuple[str, ...], Path, dict[str, str], int]] = []
        self.service_reads = 0

    def __call__(self, argv, cwd, environment, timeout):
        self.calls.append((argv, cwd, dict(environment), timeout))
        if argv[0] == acceptance_module._TERRAFORM and argv[1:] == (
            "version",
            "-json",
        ):
            return subprocess.CompletedProcess(
                argv, 0, b'{"terraform_version":"1.15.8"}', b""
            )
        if argv[0] == "/usr/bin/gcloud" and argv[1:4] == (
            "run",
            "services",
            "describe",
        ):
            self.service_reads += 1
            uid = "uid-old" if self.service_reads == 1 else self.current_uid
            return subprocess.CompletedProcess(
                argv,
                0,
                _service(uid, self.baseline),
                b"",
            )
        if argv[0] == acceptance_module._TERRAFORM and argv[2] == "plan":
            output = next(
                item.removeprefix("-out=") for item in argv if item.startswith("-out=")
            )
            _write(Path(output), b"sealed replacement plan", 0o600)
            return subprocess.CompletedProcess(argv, 0, b"planned", b"")
        if argv[0] == acceptance_module._TERRAFORM and argv[2] == "show":
            return subprocess.CompletedProcess(argv, 0, self.plan, b"")
        if argv[0] == acceptance_module._TERRAFORM and argv[2] == "apply":
            return subprocess.CompletedProcess(argv, 0, b"applied", b"")
        assert argv[0] == "/usr/bin/gcloud"
        assert argv[1:4] == ("run", "revisions", "list")
        return subprocess.CompletedProcess(
            argv,
            0,
            _revisions(self.baseline, residual=self.residual_revision),
            b"",
        )


def _reprovisioner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    release_reader: _ReleaseReader | None = None,
    extra_change: dict[str, object] | None = None,
    omit: str | None = None,
    current_uid: str = "uid-new",
    residual_revision: bool = False,
):
    binding, variables = _state(tmp_path)
    _install_terraform(tmp_path, monkeypatch)
    candidate = _candidate()
    baseline = acceptance_module._expected_canary_revision(candidate, variables)
    runner = _Runner(
        baseline=baseline,
        plan=_plan(variables, extra_change=extra_change, omit=omit),
        current_uid=current_uid,
        residual_revision=residual_revision,
    )
    reader = release_reader or _ReleaseReader()
    helper = TerraformCanaryReprovisioner(
        candidate,
        binding=binding,
        release_id=RELEASE,
        release_reader=reader,
        command_runner=runner,
        environ={"HOME": str(tmp_path)},
        clock=lambda: acceptance_module.datetime(
            2026, 8, 24, tzinfo=acceptance_module.UTC
        ),
    )
    return helper, runner, reader, binding


def test_reprovision_uses_exact_direct_plan_and_proves_clean_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, runner, reader, binding = _reprovisioner(tmp_path, monkeypatch)

    observation = asyncio.run(helper.reprovision())

    assert observation.previous_service_uid == "uid-old"
    assert observation.service_uid == "uid-new"
    assert observation.revision_names == (observation.baseline_revision,)
    assert observation.changed_resource_addresses == (
        acceptance_module._CANARY_REPROVISION_ADDRESSES
    )
    assert observation.release_record_absent
    assert reader.calls == [RELEASE]
    plan_call = next(
        call for call in runner.calls if len(call[0]) > 2 and call[0][2] == "plan"
    )
    apply_call = next(
        call for call in runner.calls if len(call[0]) > 2 and call[0][2] == "apply"
    )
    assert plan_call[0][0] == apply_call[0][0] == acceptance_module._TERRAFORM
    assert (
        plan_call[0][1] == apply_call[0][1] == ("-chdir=infra/environments/dev/runtime")
    )
    assert all(
        f"-replace={address}" in plan_call[0] and f"-target={address}" in plan_call[0]
        for address in acceptance_module._CANARY_REPROVISION_ADDRESSES
    )
    assert not any(argument in {"sh", "bash", "-c"} for argument in plan_call[0])
    assert plan_call[2]["TF_DATA_DIR"] == str(
        Path(binding.state_root) / "terraform-data" / "runtime"
    )
    assert plan_call[2]["TF_CLI_CONFIG_FILE"] == str(
        Path(binding.state_root) / "terraform.rc"
    )
    assert not (
        Path(binding.state_root) / "execution" / "canary-reprovision.lock"
    ).exists()
    assert not any(
        path.name.startswith("canary-reprovision-")
        for path in (Path(binding.state_root) / "execution").iterdir()
    )


def test_reprovision_rejects_a_wider_plan_before_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extra = {
        "address": "google_cloud_run_v2_service.api",
        "change": {
            "actions": ["update"],
            "after": {
                "location": "us-central1",
                "name": "reconcile-p5-api",
                "project": PROJECT,
            },
            "before": {
                "location": "us-central1",
                "name": "reconcile-p5-api",
                "project": PROJECT,
            },
        },
        "mode": "managed",
        "provider_name": "registry.terraform.io/hashicorp/google",
        "type": "google_cloud_run_v2_service",
    }
    helper, runner, reader, _binding = _reprovisioner(
        tmp_path,
        monkeypatch,
        extra_change=extra,
    )

    with pytest.raises(HostedAcceptanceError, match="CANARY_REPROVISION_PLAN_WIDE"):
        asyncio.run(helper.reprovision())

    assert not any(len(call[0]) > 2 and call[0][2] == "apply" for call in runner.calls)
    assert reader.calls == []


def test_reprovision_accepts_only_cloud_run_empty_collection_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _binding, variables = _state(tmp_path)
    plan = json.loads(_plan(variables))
    before = {
        "annotations": None,
        "template": [{"containers": [{"depends_on": None}]}],
    }
    after = {
        "annotations": {},
        "template": [{"containers": [{"depends_on": []}]}],
    }
    plan["resource_drift"] = [
        {
            "address": "google_cloud_run_v2_service.canary",
            "change": {"actions": ["update"], "before": before, "after": after},
            "mode": "managed",
            "provider_name": "registry.terraform.io/hashicorp/google",
            "type": "google_cloud_run_v2_service",
        }
    ]

    acceptance_module._validate_canary_reprovision_plan(
        _canonical(plan), candidate=_candidate(), variables=variables
    )

    plan["resource_drift"][0]["change"]["after"]["ingress"] = "internal"
    with pytest.raises(HostedAcceptanceError, match="CANARY_REPROVISION_PLAN_WIDE"):
        acceptance_module._validate_canary_reprovision_plan(
            _canonical(plan), candidate=_candidate(), variables=variables
        )


def test_reprovision_requires_every_directly_coupled_iam_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, runner, reader, _binding = _reprovisioner(
        tmp_path,
        monkeypatch,
        omit="google_cloud_run_v2_service_iam_member.canary_reader",
    )

    with pytest.raises(
        HostedAcceptanceError,
        match="CANARY_REPROVISION_PLAN_INCOMPLETE",
    ):
        asyncio.run(helper.reprovision())

    assert not any(len(call[0]) > 2 and call[0][2] == "apply" for call in runner.calls)
    assert reader.calls == []


@pytest.mark.parametrize(
    ("current_uid", "residual_revision", "release_record", "error"),
    (
        ("uid-old", False, None, "CANARY_REPROVISION_UID_UNCHANGED"),
        ("uid-new", True, None, "CANARY_REPROVISION_NOT_CLEAN"),
        ("uid-new", False, object(), "CANARY_RELEASE_RECORD_PRESENT"),
    ),
)
def test_reprovision_fails_closed_when_physical_cleanliness_is_unproved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    current_uid: str,
    residual_revision: bool,
    release_record: object | None,
    error: str,
) -> None:
    helper, runner, reader, _binding = _reprovisioner(
        tmp_path,
        monkeypatch,
        release_reader=_ReleaseReader(release_record),
        current_uid=current_uid,
        residual_revision=residual_revision,
    )

    with pytest.raises(HostedAcceptanceError, match=error):
        asyncio.run(helper.reprovision())

    assert any(len(call[0]) > 2 and call[0][2] == "apply" for call in runner.calls)
    if error == "CANARY_RELEASE_RECORD_PRESENT":
        assert reader.calls == [RELEASE]
    else:
        assert reader.calls == []


def test_reprovision_rejects_tampered_sealed_variables_before_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, runner, reader, binding = _reprovisioner(tmp_path, monkeypatch)
    variable_path = Path(binding.state_root) / "plans" / "runtime-create.tfvars.json"
    variable_path.chmod(0o600)
    variable_path.write_bytes(variable_path.read_bytes() + b" ")
    variable_path.chmod(0o400)

    with pytest.raises(
        HostedAcceptanceError, match="CANARY_REPROVISION_BINDING_CHANGED"
    ):
        asyncio.run(helper.reprovision())

    assert runner.calls == []
    assert reader.calls == []


def test_reprovision_rejects_a_different_terraform_backend_before_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, runner, reader, binding = _reprovisioner(tmp_path, monkeypatch)
    backend_path = (
        Path(binding.state_root) / "terraform-data" / "runtime" / "terraform.tfstate"
    )
    backend = json.loads(backend_path.read_bytes())
    backend["backend"]["config"]["prefix"] = "production/runtime"
    backend_path.write_bytes(_canonical(backend))
    backend_path.chmod(0o600)

    with pytest.raises(
        HostedAcceptanceError, match="CANARY_REPROVISION_BACKEND_INVALID"
    ):
        asyncio.run(helper.reprovision())

    assert runner.calls == []
    assert reader.calls == []
