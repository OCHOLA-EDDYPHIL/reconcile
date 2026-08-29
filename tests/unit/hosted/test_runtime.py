"""Production hosted assembly and sealed internal-gateway tests."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import FastAPI

import reconcile.hosted.runtime as hosted_runtime
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.codec import canonical_sha256, decode_contract
from reconcile.contracts.envelope import ExecutionEnvelope
from reconcile.durable_application import DurableExecutionStrategy
from reconcile.hosted.config import Component, HostedConfig
from reconcile.hosted.contracts import (
    INTERNAL_OPERATION_RESPONSE_VERSION,
    InternalOperation,
    InternalOperationRequest,
    InternalOperationResponse,
    canonical_internal_json_bytes,
)
from reconcile.hosted.runtime import (
    HostedControllerDispatcher,
    HostedFixedExecutor,
    HostedHybridExecutor,
    HostedSandboxOperationGateway,
    build_hosted_candidate,
    create_runtime_component_app,
)
from reconcile.hosted.scenario_material import build_hosted_scenario_material
from reconcile.hosted.transport import HostedHttpResponse, HostedHttpTransport
from reconcile.hosted.workflow import (
    HOSTED_OPERATION_RECEIPT_VERSION,
    HOSTED_OPERATION_SCOPE_VERSION,
    HostedOperationReceipt,
    HostedOperationScope,
    HostedWorkflowOperation,
)
from reconcile.recovery_scenario import RECOVERY_EVIDENCE_BUDGET_MS
from reconcile.scenarios.service import ScenarioMode, ScenarioName, _request

pytestmark = pytest.mark.unit

_PROJECT = "example-project-id"
_BUCKET = f"{_PROJECT}-p5-target"
_RUNTIME_DATABASE = "reconcile-p5-runtime"
_SANDBOX_DATABASE = "reconcile-p5-sandbox"
_TARGET_DATABASE = "reconcile-p5-target"
_API = f"rec-p5-api@{_PROJECT}.iam.gserviceaccount.com"
_CONTROLLER = f"rec-p5-controller@{_PROJECT}.iam.gserviceaccount.com"
_FAULT = f"rec-p5-fault@{_PROJECT}.iam.gserviceaccount.com"
_PROMPT_SHA = "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"


def _audience(component: Component) -> str:
    return f"https://reconcile.invalid/phase5/{_PROJECT}/{component.value}"


def _config(component: Component) -> HostedConfig:
    common: dict[str, object] = {
        "component": component,
        "port": 8080,
        "project_id": _PROJECT,
        "auth_audience": _audience(component),
        "source_revision": "a" * 40,
        "image_digest": f"sha256:{'b' * 64}",
        "infra_revision": "c" * 64,
        "semantic_config_sha256": "d" * 64,
    }
    if component is Component.API:
        values = {
            "allowed_caller_emails": (
                f"rec-p5-apply@{_PROJECT}.iam.gserviceaccount.com",
            ),
            "runtime_database": _RUNTIME_DATABASE,
            "target_bucket": _BUCKET,
            "controller_url": "https://controller.example.test",
            "controller_audience": _audience(Component.CONTROLLER),
            "fault_proxy_url": "https://fault.example.test",
            "fault_proxy_audience": _audience(Component.FAULT_PROXY),
        }
    elif component is Component.CONTROLLER:
        values = {
            "allowed_caller_emails": (_API,),
            "runtime_database": _RUNTIME_DATABASE,
            "target_database": _TARGET_DATABASE,
            "target_bucket": _BUCKET,
            "fault_proxy_url": "https://fault.example.test",
            "fault_proxy_audience": _audience(Component.FAULT_PROXY),
            "sandbox_url": "https://sandbox.example.test",
            "sandbox_audience": _audience(Component.SANDBOX),
            "canary_location": "us-central1",
            "canary_service": "reconcile-p5-canary",
            "canary_baseline_revision": "reconcile-p5-canary-b-0123456789abcdef",
            "canary_audience": (f"https://reconcile.invalid/phase5/{_PROJECT}/canary"),
            "recovery_release_id": f"p5-release-{'a' * 24}",
            "recovery_payload_sha256": "e" * 64,
            "recovery_definition_created_at": datetime(2026, 8, 24, tzinfo=UTC),
            "recovery_execution_timeout_seconds": 240,
            "vertex_location": "us",
            "vertex_model": "gemini-3.5-flash",
            "vertex_prompt_version": "adaptive-planner-v3",
            "vertex_prompt_sha256": _PROMPT_SHA,
            "vertex_max_count_tokens_attempts": 1,
            "vertex_max_generation_attempts": 1,
            "vertex_max_input_tokens": 12_000,
            "vertex_max_output_tokens": 4_096,
            "vertex_thinking_level": "MINIMAL",
        }
    elif component is Component.FAULT_PROXY:
        values = {
            "allowed_caller_emails": (_API,),
            "runtime_database": _RUNTIME_DATABASE,
            "target_database": _TARGET_DATABASE,
            "target_bucket": _BUCKET,
            "sandbox_url": "https://sandbox.example.test",
            "sandbox_audience": _audience(Component.SANDBOX),
            "canary_location": "us-central1",
            "canary_service": "reconcile-p5-canary",
            "canary_baseline_revision": "reconcile-p5-canary-b-0123456789abcdef",
            "canary_audience": (f"https://reconcile.invalid/phase5/{_PROJECT}/canary"),
            "recovery_action_caller_email": _CONTROLLER,
        }
    else:
        values = {
            "allowed_caller_emails": (_CONTROLLER, _FAULT),
            "runtime_database": _RUNTIME_DATABASE,
            "target_database": _SANDBOX_DATABASE,
            "sandbox_read_caller_email": _CONTROLLER,
            "sandbox_mutation_caller_email": _FAULT,
        }
    config = HostedConfig(**common, **values)  # type: ignore[arg-type]
    if component is Component.CONTROLLER:
        config = replace(
            config,
            recovery_payload_sha256=build_hosted_candidate(config).sha256,
        )
    return config


def _scope(operation: HostedWorkflowOperation) -> HostedOperationScope:
    return HostedOperationScope(
        schema_version=HOSTED_OPERATION_SCOPE_VERSION,
        operation=operation,
        launch_id="launch-runtime",
        launch_sha256="1" * 64,
        scenario_request_sha256="2" * 64,
        investigation_id="investigation-runtime",
        operation_id="operation-runtime",
        invocation_id="invocation-runtime",
        function_call_id="function-call-runtime",
        envelope_sha256="3" * 64,
        cleanup_manifest_sha256="4" * 64,
        lease_fence=1,
    )


def _envelope(scenario: ScenarioName) -> ExecutionEnvelope:
    return build_hosted_scenario_material(
        _request(scenario, "runtime-routing"),
        invoked_at=datetime(2026, 8, 18, tzinfo=UTC),
        target_bucket=_BUCKET,
    ).preparation.execution_envelope


class _CompletionRuntime:
    def __init__(self) -> None:
        self.reports: list[object] = []

    async def complete(self, report: object) -> object:
        self.reports.append(report)
        return report


def test_every_component_assembles_one_identical_candidate_without_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_io(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("hosted construction attempted provider or network I/O")

    monkeypatch.setattr(socket, "socket", deny_io)
    monkeypatch.setattr(
        hosted_runtime.AdkGeminiPlanner,
        "from_vertex_adc_guarded",
        deny_io,
    )
    configs = tuple(_config(component) for component in Component)
    candidates = tuple(build_hosted_candidate(config) for config in configs)

    assert len({candidate.sha256 for candidate in candidates}) == 1
    for config in configs:
        application = create_runtime_component_app(config)
        assert type(application) is FastAPI
        assert application.state.hosted_config is config


def test_runtime_transport_timeouts_are_component_scoped() -> None:
    transports = {
        component: create_runtime_component_app(
            _config(component)
        ).state.hosted_transport
        for component in (
            Component.API,
            Component.CONTROLLER,
            Component.FAULT_PROXY,
            Component.SANDBOX,
        )
    }

    assert {
        component: (
            transport._request_timeout_seconds,
            transport._total_timeout_seconds,
        )
        for component, transport in transports.items()
    } == {
        Component.API: (265.0, 270.0),
        Component.CONTROLLER: (265.0, 270.0),
        Component.FAULT_PROXY: (10.0, 15.0),
        Component.SANDBOX: (10.0, 15.0),
    }


def test_recovery_provider_timeout_preserves_fixed_fallback_budget() -> None:
    assert (
        RECOVERY_EVIDENCE_BUDGET_MS
        - int(hosted_runtime._HOSTED_RECOVERY_PROVIDER_TIMEOUT_SECONDS * 1_000)
        >= 30_000
    )


def test_fault_proxy_recovery_actions_use_durable_authorizers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    sentinel = object()

    def capture(_config: HostedConfig, **kwargs: object) -> object:
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(hosted_runtime, "create_component_app", capture)

    result = create_runtime_component_app(_config(Component.FAULT_PROXY))

    assert result is sentinel
    assert type(captured["cloud_run_canary_action_authorizer"]) is (
        hosted_runtime.RecoveryCloudRunCanaryActionAuthorizer
    )
    assert type(captured["firestore_release_action_authorizer"]) is (
        hosted_runtime.RecoveryFirestoreReleaseActionAuthorizer
    )
    assert captured["recovery_action_caller_email"] == _CONTROLLER


@pytest.mark.parametrize(
    "component",
    (Component.API, Component.CONTROLLER, Component.FAULT_PROXY),
)
def test_acceptance_partial_read_outage_enablement_reaches_each_runtime_boundary(
    monkeypatch: pytest.MonkeyPatch,
    component: Component,
) -> None:
    captured: dict[str, object] = {}
    sentinel = object()

    def capture(_config: HostedConfig, **kwargs: object) -> object:
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(hosted_runtime, "create_component_app", capture)
    config = replace(
        _config(component),
        acceptance_partial_read_outage_enabled=True,
    )

    assert create_runtime_component_app(config) is sentinel
    assert captured["acceptance_partial_read_outage_enabled"] is True
    if component is Component.API:
        assert (
            captured["recovery_service"]._acceptance_partial_read_outage_enabled is True
        )
    elif component is Component.CONTROLLER:
        handlers = captured["internal_operation_handlers"]
        assert isinstance(handlers, dict)
        recovery = handlers[InternalOperation.RECOVER]
        assert recovery._acceptance_partial_read_outage_enabled is True
    else:
        authorizer = captured["cloud_run_canary_action_authorizer"]
        assert authorizer._acceptance_partial_read_outage_enabled is True


def test_controller_registers_lazy_recovery_with_manifest_bound_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    sentinel = object()

    def capture(_config: HostedConfig, **kwargs: object) -> object:
        captured.update(kwargs)
        return sentinel

    def deny_planner(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("controller startup constructed the recovery planner")

    monkeypatch.setattr(hosted_runtime, "create_component_app", capture)
    monkeypatch.setattr(
        hosted_runtime.AdkGeminiPlanner,
        "from_vertex_adc_guarded",
        deny_planner,
    )
    config = _config(Component.CONTROLLER)

    result = create_runtime_component_app(config)

    assert result is sentinel
    handlers = captured["internal_operation_handlers"]
    assert isinstance(handlers, dict)
    assert (
        type(handlers[InternalOperation.RECOVER])
        is hosted_runtime.HostedRecoveryHandler
    )
    settings, invoked_at, timeout = hosted_runtime._release_chain_settings(
        config,
        build_hosted_candidate(config),
    )
    assert settings.release_id == f"p5-release-{'a' * 24}"
    assert settings.payload_sha256 == build_hosted_candidate(config).sha256
    assert invoked_at == datetime(2026, 8, 24, tzinfo=UTC)
    assert timeout == 240


def test_fixed_executor_routes_storage_and_firestore_to_fixed_connectors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        storage_reader = object()
        firestore_reader = object()
        calls: list[tuple[str, object, str]] = []

        async def storage(
            envelope: ExecutionEnvelope,
            reader: object,
            **_kwargs: object,
        ) -> SimpleNamespace:
            calls.append(("storage", reader, envelope.target.target_kind))
            return SimpleNamespace(report="storage-report")

        async def firestore(
            envelope: ExecutionEnvelope,
            reader: object,
            **_kwargs: object,
        ) -> SimpleNamespace:
            calls.append(("firestore", reader, envelope.target.target_kind))
            return SimpleNamespace(report="firestore-report")

        async def sandbox(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("fixed storage/Firestore route reached sandbox")

        monkeypatch.setattr(hosted_runtime, "execute_cloud_storage_baseline", storage)
        monkeypatch.setattr(
            hosted_runtime,
            "execute_cloud_firestore_business_baseline",
            firestore,
        )
        monkeypatch.setattr(
            hosted_runtime,
            "execute_hosted_sandbox_order_fixed",
            sandbox,
        )
        monkeypatch.setattr(
            hosted_runtime,
            "mark_bounded_hybrid_deterministic_fixed",
            lambda report: f"fixed:{report}",
        )
        executor = HostedFixedExecutor(
            storage_reader=storage_reader,  # type: ignore[arg-type]
            firestore_reader=firestore_reader,  # type: ignore[arg-type]
            sandbox_url="https://sandbox.example.test",
            sandbox_audience=_audience(Component.SANDBOX),
            transport=HostedHttpTransport(),
        )
        runtime = _CompletionRuntime()
        cancellation = asyncio.Event()

        assert (
            await executor(
                _envelope(ScenarioName.STORAGE),
                revision=1,
                cancellation_event=cancellation,
                runtime=runtime,  # type: ignore[arg-type]
            )
            == "fixed:storage-report"
        )
        assert (
            await executor(
                _envelope(ScenarioName.FIRESTORE_BUSINESS),
                revision=2,
                cancellation_event=cancellation,
                runtime=runtime,  # type: ignore[arg-type]
            )
            == "fixed:firestore-report"
        )
        assert calls == [
            ("storage", storage_reader, "storage.object"),
            ("firestore", firestore_reader, "business.documents"),
        ]
        assert runtime.reports == ["fixed:storage-report", "fixed:firestore-report"]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "scenario_name",
    (ScenarioName.STORAGE, ScenarioName.FIRESTORE_BUSINESS),
)
def test_hybrid_executor_rejects_authoritative_routes_before_planner_construction(
    scenario_name: ScenarioName,
) -> None:
    planner_calls = 0

    def planner_factory():
        nonlocal planner_calls
        planner_calls += 1
        raise AssertionError("authoritative route attempted adaptive planning")

    fixed = HostedFixedExecutor(
        storage_reader=object(),  # type: ignore[arg-type]
        firestore_reader=object(),  # type: ignore[arg-type]
        sandbox_url="https://sandbox.example.test",
        sandbox_audience=_audience(Component.SANDBOX),
        transport=HostedHttpTransport(),
    )
    executor = HostedHybridExecutor(fixed=fixed, planner_factory=planner_factory)

    async def scenario() -> None:
        with pytest.raises(ValueError, match="sandbox-only"):
            await executor(
                _envelope(scenario_name),
                revision=1,
                cancellation_event=asyncio.Event(),
                runtime=_CompletionRuntime(),  # type: ignore[arg-type]
            )

    asyncio.run(scenario())
    assert planner_calls == 0


@pytest.mark.parametrize(
    ("scenario_name", "mode", "expected_strategy"),
    (
        (
            ScenarioName.STORAGE,
            ScenarioMode.ADAPTIVE,
            DurableExecutionStrategy.FIXED,
        ),
        (
            ScenarioName.FIRESTORE_BUSINESS,
            ScenarioMode.ADAPTIVE,
            DurableExecutionStrategy.FIXED,
        ),
        (
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.ADAPTIVE,
            DurableExecutionStrategy.ADAPTIVE,
        ),
        (
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.FIXED,
            DurableExecutionStrategy.FIXED,
        ),
    ),
)
def test_controller_selects_service_and_starts_evidence_budget_locally(
    scenario_name: ScenarioName,
    mode: ScenarioMode,
    expected_strategy: DurableExecutionStrategy,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = build_hosted_scenario_material(
        _request(scenario_name, "runtime-controller-route"),
        invoked_at=datetime(2026, 8, 18, tzinfo=UTC),
        target_bucket=_BUCKET,
    )
    envelope = material.preparation.execution_envelope
    work = SimpleNamespace(
        scenario_result=SimpleNamespace(execution_envelope=envelope),
        launch_request=SimpleNamespace(mode=SimpleNamespace(value=mode.value)),
        updated_at=datetime(2026, 8, 18, tzinfo=UTC),
    )
    selected: list[tuple[DurableExecutionStrategy, dict[str, object]]] = []

    class _RouteSelected(Exception):
        pass

    class _Service:
        def __init__(
            self,
            _store: object,
            _executor: object,
            *,
            strategy: DurableExecutionStrategy,
            **_kwargs: object,
        ) -> None:
            self.strategy = strategy

        async def create_and_wait_result(self, *_args: object, **kwargs: object):
            selected.append((self.strategy, kwargs))
            raise _RouteSelected

    async def sealed(*_args: object, **_kwargs: object):
        return work, material

    monkeypatch.setattr(
        hosted_runtime,
        "DurableInvestigationApplicationService",
        _Service,
    )
    monkeypatch.setattr(hosted_runtime, "_sealed_material", sealed)
    candidate = build_hosted_candidate(_config(Component.CONTROLLER))
    dispatcher = HostedControllerDispatcher(
        store=object(),  # type: ignore[arg-type]
        candidate=candidate,
        target_bucket=_BUCKET,
        runtime_store=object(),  # type: ignore[arg-type]
        fixed_executor=object(),  # type: ignore[arg-type]
        hybrid_executor=object(),  # type: ignore[arg-type]
    )
    scope = _scope(HostedWorkflowOperation.INVESTIGATE).model_copy(
        update={
            "investigation_id": envelope.investigation_id,
            "operation_id": envelope.operation_id,
            "envelope_sha256": canonical_sha256(envelope),
            "cleanup_manifest_sha256": material.preparation.cleanup_manifest_sha256,
        }
    )

    async def scenario() -> None:
        with pytest.raises(_RouteSelected):
            await dispatcher(scope)

    asyncio.run(scenario())
    assert selected == [(expected_strategy, {})]


@pytest.mark.parametrize(
    ("scope_update", "resource_update"),
    (
        ({"environment": "local-sandbox-sqlite"}, {}),
        ({"unexpected": "scope"}, {}),
        ({}, {"observation_set": "unapproved-observations"}),
    ),
)
def test_hybrid_executor_rejects_nonexact_sandbox_scope_before_planner_construction(
    scope_update: dict[str, str],
    resource_update: dict[str, str],
) -> None:
    envelope = _envelope(ScenarioName.SANDBOX_ORDER)
    target = envelope.target.model_copy(
        update={
            "scope": {**envelope.target.scope, **scope_update},
            "resource": {**envelope.target.resource, **resource_update},
        }
    )
    tampered = envelope.model_copy(update={"target": target})
    planner_calls = 0

    def planner_factory():
        nonlocal planner_calls
        planner_calls += 1
        raise RuntimeError("planner must not be constructed")

    fixed = HostedFixedExecutor(
        storage_reader=object(),  # type: ignore[arg-type]
        firestore_reader=object(),  # type: ignore[arg-type]
        sandbox_url="https://sandbox.example.test",
        sandbox_audience=_audience(Component.SANDBOX),
        transport=HostedHttpTransport(),
    )
    executor = HostedHybridExecutor(fixed=fixed, planner_factory=planner_factory)

    async def scenario() -> None:
        with pytest.raises(ValueError):
            await executor(
                tampered,
                revision=1,
                cancellation_event=asyncio.Event(),
                runtime=_CompletionRuntime(),  # type: ignore[arg-type]
            )

    asyncio.run(scenario())
    assert planner_calls == 0


def test_sandbox_operation_gateway_sends_only_the_exact_scope_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        transport = HostedHttpTransport()
        calls: list[tuple[str, str, str, bytes]] = []

        async def request(
            method: str,
            url: str,
            *,
            audience: str,
            content: bytes = b"",
        ) -> HostedHttpResponse:
            calls.append((method, url, audience, content))
            internal = decode_contract(content, InternalOperationRequest)
            scope = HostedOperationScope.model_validate_json(
                canonical_json_value_bytes(internal.payload)
            )
            receipt = HostedOperationReceipt(
                schema_version=HOSTED_OPERATION_RECEIPT_VERSION,
                operation=scope.operation,
                scope_sha256=scope.sha256,
                started_at=datetime(2026, 8, 18, tzinfo=UTC),
                completed_at=datetime(2026, 8, 18, tzinfo=UTC),
            )
            response = InternalOperationResponse(
                schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
                request_id=internal.request_id,
                operation=internal.operation,
                accepted=True,
                payload=receipt.model_dump(mode="json"),
            )
            return HostedHttpResponse(
                status_code=200,
                content=canonical_internal_json_bytes(response),
            )

        monkeypatch.setattr(transport, "request", request)
        gateway = HostedSandboxOperationGateway(
            sandbox_url="https://sandbox.example.test",
            sandbox_audience=_audience(Component.SANDBOX),
            transport=transport,
        )
        mutation = _scope(HostedWorkflowOperation.EXECUTE_FAULT)
        cleanup = _scope(HostedWorkflowOperation.CLEANUP)
        assert (await gateway.execute_fault(mutation)).scope_sha256 == mutation.sha256
        assert (await gateway.cleanup(cleanup)).scope_sha256 == cleanup.sha256
        assert [call[1] for call in calls] == [
            "https://sandbox.example.test/internal/v1/mutations",
            "https://sandbox.example.test/internal/v1/cleanup",
        ]
        for _, _, _, content in calls:
            internal = decode_contract(content, InternalOperationRequest)
            assert set(internal.payload) == set(HostedOperationScope.model_fields)

    asyncio.run(scenario())
