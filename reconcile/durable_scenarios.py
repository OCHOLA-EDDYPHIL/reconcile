"""Durable orchestration for the three real operator scenarios."""

from __future__ import annotations

import asyncio
import hashlib
import os
import stat
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from reconcile.adaptive import AdvisoryPlanner
from reconcile.adk_planner import AdkGeminiPlanner, VertexAdcPlannerConfig
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.codec import canonical_json_bytes, canonical_sha256
from reconcile.contracts.comparison import (
    INVESTIGATION_COMPARISON_RECORD_VERSION,
    InvestigationComparisonRecord,
)
from reconcile.contracts.operator import (
    ScenarioLaunchRequest,
    ScenarioRunEvent,
    ScenarioRunSnapshot,
)
from reconcile.contracts.report import InvestigationReport, InvestigationStatus
from reconcile.contracts.scenario import ScenarioCleanupDisposition
from reconcile.durable_application import (
    DurableEscalationRequired,
    DurableExecutionContext,
    DurableExecutionOutcome,
    DurableExecutionStrategy,
    DurableInvestigationApplicationService,
)
from reconcile.durable_planner import DurableAdvisoryPlanner
from reconcile.persistence import (
    CleanupStatus,
    ScenarioInvestigationState,
    ScenarioLane,
    ScenarioLeaseToken,
    ScenarioLeaseUnavailable,
    ScenarioMutationState,
    ScenarioWorkItem,
    SqliteDurableRuntimeStore,
    SqliteScenarioStore,
    StaleScenarioLease,
)
from reconcile.progress import (
    EnvelopeProgress,
    ProgressCallback,
    ProgressDispatcher,
    ProgressEmitter,
)
from reconcile.runtime_provenance import build_runtime_provenance
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.service import (
    _RECIPES,
    ScenarioMode,
    ScenarioName,
    ScenarioWorkflowError,
    ScenarioWorkflowErrorCategory,
    ScenarioWorkflowResult,
    _adaptive_comparison_run,
    _definition,
    _envelope_summary,
    _expectation,
    _fixed_comparison_run,
    _fixed_investigation,
    _request,
    _seed_sandbox_fixture,
)

_PLANNER_MAX_CALLS = 64
_PLANNER_CALL_COST_MICROUNITS = 1
_POLL_SECONDS = 0.02


def _now() -> datetime:
    return datetime.now(UTC)


def _workspace_id(investigation_id: str) -> str:
    digest = hashlib.sha256(investigation_id.encode("utf-8")).hexdigest()
    return f"scenario-workspace-{digest[:32]}"


def _strategy_sha256(scenario: ScenarioName, mode: ScenarioMode) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes(
            {
                "mode": mode.value,
                "scenario": scenario.value,
                "version": "durable-scenario-strategy-v1",
            }
        )
    ).hexdigest()


class _ScenarioAuthority:
    def __init__(
        self,
        store: SqliteScenarioStore,
        token: ScenarioLeaseToken,
        clock: Callable[[], datetime],
    ) -> None:
        self._store = store
        self._token = token
        self._clock = clock
        self._lock = asyncio.Lock()
        self._released = False

    @asynccontextmanager
    async def hold(self) -> AsyncIterator[ScenarioLeaseToken]:
        async with self._lock:
            if self._released:
                raise StaleScenarioLease(self._token.investigation_id)
            now = max(self._clock(), self._token.renewed_at)
            if now >= self._token.expires_at:
                raise StaleScenarioLease(self._token.investigation_id)
            if (self._token.expires_at - now).total_seconds() <= 20:
                self._token = await self._store.renew_scenario_lease(
                    self._token,
                    now=now,
                )
            yield self._token

    async def renew(self) -> None:
        async with self._lock:
            if self._released:
                return
            now = max(self._clock(), self._token.renewed_at)
            self._token = await self._store.renew_scenario_lease(
                self._token,
                now=now,
            )

    async def release(self) -> None:
        async with self._lock:
            if self._released:
                return
            try:
                await self._store.release_scenario_lease(
                    self._token,
                    now=max(self._clock(), self._token.renewed_at),
                )
            except StaleScenarioLease:
                pass
            self._released = True


class _FixedScenarioExecutor:
    def __init__(
        self,
        *,
        scenario: ScenarioName,
        workspace: Path,
        expectation,
        progress_emitter: ProgressEmitter | None,
        lane_recorder: Callable[[ScenarioLane, object], object] | None,
    ) -> None:
        self._scenario = scenario
        self._workspace = workspace
        self._expectation = expectation
        self._progress_emitter = progress_emitter
        self._lane_recorder = lane_recorder

    async def __call__(
        self,
        envelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
        runtime: DurableExecutionContext,
    ) -> DurableExecutionOutcome:
        result = await _fixed_investigation(
            self._scenario,
            self._workspace,
            envelope,
            cancellation_event=cancellation_event,
            progress_emitter=self._progress_emitter,
            revision=revision,
            durability_observer=runtime,
        )
        if self._lane_recorder is not None:
            comparison = _fixed_comparison_run(
                self._scenario,
                canonical_sha256(envelope),
                self._expectation,
                result,
            )
            await self._lane_recorder(ScenarioLane.FIXED, comparison)  # type: ignore[misc]
        return await runtime.complete(result.report)


class _AdaptiveScenarioExecutor:
    def __init__(
        self,
        *,
        scenario: ScenarioName,
        definition,
        planner_factory: Callable[[ScenarioName], AdvisoryPlanner],
        expectation,
        progress_emitter: ProgressEmitter | None,
        lane_recorder: Callable[[ScenarioLane, object], object] | None,
    ) -> None:
        self._scenario = scenario
        self._definition = definition
        self._planner_factory = planner_factory
        self._expectation = expectation
        self._progress_emitter = progress_emitter
        self._lane_recorder = lane_recorder

    async def __call__(
        self,
        envelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
        runtime: DurableExecutionContext,
    ) -> DurableExecutionOutcome:
        planner = self._planner_factory(self._scenario)
        durable_planner = DurableAdvisoryPlanner(
            planner,
            runtime,
            estimated_cost_microunits=_PLANNER_CALL_COST_MICROUNITS,
        )
        try:
            result = await self._definition.adaptive(
                envelope,
                durable_planner,
                revision=revision,
                cancellation_event=cancellation_event,
                progress_emitter=self._progress_emitter,
                durability_observer=runtime,
            )
        finally:
            closer = getattr(planner, "aclose", None)
            if callable(closer):
                closed = closer()
                if hasattr(closed, "__await__"):
                    await closed
        if self._lane_recorder is not None:
            comparison = _adaptive_comparison_run(
                self._scenario,
                canonical_sha256(envelope),
                self._expectation,
                result,
            )
            await self._lane_recorder(ScenarioLane.ADAPTIVE, comparison)  # type: ignore[misc]
        return await runtime.complete(result.report)


class DurableScenarioWorkflow:
    """Bind mutation, durable child reads, result, and cleanup in that order."""

    def __init__(
        self,
        store: SqliteScenarioStore,
        workspace_root: str | Path,
        *,
        semantic_config_sha256: str,
        vertex_config: VertexAdcPlannerConfig | None = None,
        planner_factory: Callable[[ScenarioName], AdvisoryPlanner] | None = None,
        owner_id: str = "operator",
        clock: Callable[[], datetime] = _now,
    ) -> None:
        if not isinstance(store, SqliteScenarioStore):
            raise TypeError("durable scenario workflow requires its exact store")
        if (vertex_config is None) is (planner_factory is None):
            if vertex_config is not None:
                raise ValueError("durable planner configuration is ambiguous")
        if vertex_config is not None and vertex_config.credentials is not None:
            raise ValueError("durable scenarios require ambient ADC")
        root = Path(workspace_root)
        resolved = root.resolve(strict=True)
        metadata = resolved.stat()
        if (
            not root.is_absolute()
            or root != resolved
            or root.is_symlink()
            or not resolved.is_dir()
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise ValueError("scenario workspace root must be user-owned and private")
        if not re_full_digest(semantic_config_sha256):
            raise ValueError("scenario semantic configuration must be a SHA-256 digest")
        self._store = store
        self._workspace_root = resolved
        self._semantic_config_sha256 = semantic_config_sha256
        self._vertex_config = vertex_config
        self._supplied_planner_factory = planner_factory
        self._owner_id = owner_id
        self._clock = clock

    def _runtime_provenance(self, mode: ScenarioMode) -> str:
        return build_runtime_provenance(
            executor=self,
            cleanup=None,
            strategy=mode.value,
            max_provider_calls=(
                0 if mode is ScenarioMode.FIXED else _PLANNER_MAX_CALLS
            ),
            max_estimated_cost_microunits=(
                0 if mode is ScenarioMode.FIXED else _PLANNER_MAX_CALLS
            ),
            semantic_config_sha256=self._semantic_config_sha256,
        ).sha256

    @property
    def provider_available(self) -> bool:
        return (
            self._vertex_config is not None
            or self._supplied_planner_factory is not None
        )

    async def bind_launch(
        self,
        launch: ScenarioLaunchRequest,
        *,
        snapshot: ScenarioRunSnapshot,
        accepted_event: ScenarioRunEvent,
    ):
        """Persist canonical authority before the operator starts its task."""

        scenario = ScenarioName(launch.scenario.value)
        mode = ScenarioMode(launch.mode.value)
        scenario_request = _request(scenario, launch.launch_id)
        workspace_id = _workspace_id(scenario_request.investigation_id)
        workspace = self._workspace_root / workspace_id
        if workspace.is_symlink():
            raise ValueError("scenario workspace identity is not canonical")
        result = await self._store.create_work(
            launch,
            scenario_request,
            strategy_sha256=_strategy_sha256(scenario, mode),
            semantic_config_sha256=self._semantic_config_sha256,
            runtime_provenance_sha256=self._runtime_provenance(mode),
            workspace_id=workspace_id,
            invoked_at=snapshot.accepted_at,
            snapshot=snapshot,
            accepted_event=accepted_event,
            created_at=snapshot.accepted_at,
        )
        try:
            workspace.mkdir(mode=0o700)
        except FileExistsError:
            pass
        if workspace.is_symlink():
            raise ValueError("scenario workspace identity is not canonical")
        try:
            resolved = workspace.resolve(strict=True)
            metadata = workspace.stat()
        except OSError as error:
            raise ValueError("scenario workspace identity is not canonical") from error
        if (
            resolved != workspace
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise ValueError("scenario workspace must be user-owned and private")
        return result

    async def audit_terminal_projection(self, investigation_id: str) -> None:
        """Audit private authority even when the non-authoritative v1 journal ended."""

        token = await self._acquire(investigation_id, None)
        authority = _ScenarioAuthority(self._store, token, self._clock)
        try:
            work = await self._store.get_work(investigation_id)
            if (
                work.investigation_state
                is ScenarioInvestigationState.ESCALATION_REQUIRED
            ):
                return
            scenario = ScenarioName(work.launch_request.scenario.value)
            mode = ScenarioMode(work.launch_request.mode.value)
            workspace = await self._validated_workspace(
                work,
                scenario,
                mode,
                authority,
            )
            if work.investigation_state is ScenarioInvestigationState.RECORDED:
                if mode is ScenarioMode.COMPARE:
                    comparison = work.workflow_result
                    if (
                        type(comparison) is not InvestigationComparisonRecord
                        or comparison.adaptive is None
                        or await self._store.get_lane_result(
                            investigation_id,
                            ScenarioLane.FIXED,
                        )
                        != comparison.baseline
                        or await self._store.get_lane_result(
                            investigation_id,
                            ScenarioLane.ADAPTIVE,
                        )
                        != comparison.adaptive
                    ):
                        raise self._execution_failed(scenario)
                await self._recover_or_run_cleanup(
                    work,
                    scenario,
                    workspace,
                    authority,
                )
                return
            failure_code = (
                "mutation-outcome-unknown"
                if work.mutation_state is ScenarioMutationState.STARTED
                and work.scenario_result is None
                else "terminal-projection-authority-conflict"
            )
            await self._escalate(authority, failure_code)
        finally:
            await self._release_authority(authority)

    def _planner_factory(self, scenario: ScenarioName) -> AdvisoryPlanner:
        if self._supplied_planner_factory is not None:
            return self._supplied_planner_factory(scenario)
        if self._vertex_config is None:
            raise ScenarioWorkflowError(
                ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION,
                scenario=scenario,
            )
        return AdkGeminiPlanner.from_vertex_adc(self._vertex_config)

    async def __call__(
        self,
        scenario: ScenarioName,
        mode: ScenarioMode,
        *,
        vertex_config: VertexAdcPlannerConfig | None,
        run_id: str,
        progress_callback: ProgressCallback | None,
        cancellation_event: asyncio.Event | None,
    ) -> ScenarioWorkflowResult:
        del vertex_config
        request = _request(scenario, run_id)
        try:
            token = await self._acquire(request.investigation_id, cancellation_event)
        except asyncio.CancelledError:
            raise
        authority = _ScenarioAuthority(self._store, token, self._clock)
        heartbeat_stop = asyncio.Event()
        heartbeat = asyncio.create_task(
            self._heartbeat(authority, heartbeat_stop),
            name=f"reconcile-scenario-lease-{request.investigation_id}",
        )
        dispatcher = (
            None if progress_callback is None else ProgressDispatcher(progress_callback)
        )
        emitter = None if dispatcher is None else dispatcher.emit
        try:
            result = await self._run_owned(
                scenario,
                mode,
                request.investigation_id,
                authority,
                emitter,
                cancellation_event,
            )
            if dispatcher is not None:
                await dispatcher.finish()
            return result
        except asyncio.CancelledError:
            if dispatcher is not None:
                await dispatcher.abort()
            raise
        except Exception:
            if dispatcher is not None:
                with suppress(Exception):
                    await dispatcher.finish()
            raise
        finally:
            heartbeat_stop.set()
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)
            await self._release_authority(authority)

    @staticmethod
    async def _release_authority(authority: _ScenarioAuthority) -> None:
        task = asyncio.create_task(authority.release())
        interrupted = False
        while True:
            try:
                await asyncio.shield(task)
                break
            except asyncio.CancelledError:
                if task.done():
                    await task
                    raise
                interrupted = True
        if interrupted:
            raise asyncio.CancelledError

    async def _acquire(
        self,
        investigation_id: str,
        cancellation_event: asyncio.Event | None,
    ) -> ScenarioLeaseToken:
        owner = f"scenario-{hashlib.sha256(f'{self._owner_id}:{uuid4().hex}'.encode()).hexdigest()[:32]}"
        while True:
            if cancellation_event is not None and cancellation_event.is_set():
                raise asyncio.CancelledError
            try:
                return await self._store.acquire_scenario_lease(
                    investigation_id,
                    owner,
                    now=self._clock(),
                )
            except ScenarioLeaseUnavailable:
                await asyncio.sleep(_POLL_SECONDS)

    async def _heartbeat(
        self,
        authority: _ScenarioAuthority,
        stopped: asyncio.Event,
    ) -> None:
        while not stopped.is_set():
            try:
                await asyncio.wait_for(stopped.wait(), timeout=5.0)
            except TimeoutError:
                await authority.renew()

    async def _run_owned(
        self,
        scenario: ScenarioName,
        mode: ScenarioMode,
        investigation_id: str,
        authority: _ScenarioAuthority,
        progress_emitter: ProgressEmitter | None,
        cancellation_event: asyncio.Event | None,
    ) -> ScenarioWorkflowResult:
        work = await self._store.get_work(investigation_id)
        workspace = await self._validated_workspace(
            work,
            scenario,
            mode,
            authority,
        )

        if work.investigation_state is ScenarioInvestigationState.ESCALATION_REQUIRED:
            raise self._execution_failed(scenario)
        if work.workflow_result is not None:
            if (
                work.scenario_result is None
                or work.scenario_result.execution_envelope is None
            ):
                await self._escalate(authority, "terminal-envelope-binding-missing")
                raise self._execution_failed(scenario)
            if progress_emitter is not None:
                envelope = work.scenario_result.execution_envelope
                progress_emitter(
                    EnvelopeProgress(
                        occurred_at=self._clock(),
                        investigation_id=investigation_id,
                        summary=_envelope_summary(envelope),
                    )
                )
            await self._recover_or_run_cleanup(work, scenario, workspace, authority)
            return work.workflow_result
        if work.mutation_state is ScenarioMutationState.STARTED:
            await self._escalate(authority, "mutation-outcome-unknown")
            raise self._execution_failed(scenario)

        definition = _definition(
            scenario,
            workspace,
            invoked_at=work.invoked_at,
            seed_sandbox=False,
        )
        runner = ScenarioRunner()
        if work.mutation_state is ScenarioMutationState.NOT_STARTED:
            prepared = runner.prepare(work.scenario_request, definition)
            async with authority.hold() as token:
                work = await self._store.record_mutation_started(
                    token,
                    prepared_envelope_sha256=hashlib.sha256(
                        prepared.execution_envelope_bytes
                    ).hexdigest(),
                    cleanup_manifest_sha256=prepared.cleanup_manifest_sha256,
                    occurred_at=self._clock(),
                )
            if scenario is ScenarioName.SANDBOX_ORDER:
                _seed_sandbox_fixture(workspace)
            mutation_task = asyncio.create_task(
                asyncio.to_thread(
                    runner.run_prepared,
                    work.scenario_request,
                    definition,
                    prepared,
                )
            )
            cancelled = False
            try:
                scenario_result = await asyncio.shield(mutation_task)
            except asyncio.CancelledError:
                cancelled = True
                scenario_result = await mutation_task
            async with authority.hold() as token:
                work = await self._store.record_mutation_result(
                    token,
                    scenario_result,
                    prepared_envelope_bytes=prepared.execution_envelope_bytes,
                    occurred_at=self._clock(),
                )
            if cancelled:
                raise asyncio.CancelledError

        scenario_result = work.scenario_result
        if scenario_result is None or scenario_result.execution_envelope is None:
            await self._escalate(authority, "execution-envelope-unavailable")
            raise self._execution_failed(scenario)
        envelope = scenario_result.execution_envelope
        if progress_emitter is not None:
            progress_emitter(
                EnvelopeProgress(
                    occurred_at=self._clock(),
                    investigation_id=investigation_id,
                    summary=_envelope_summary(envelope),
                )
            )

        recovering = work.investigation_state is ScenarioInvestigationState.STARTED
        if work.investigation_state is ScenarioInvestigationState.NOT_STARTED:
            async with authority.hold() as token:
                work = await self._store.mark_investigation_started(
                    token,
                    occurred_at=self._clock(),
                )
        try:
            workflow_result = await self._investigate_durably(
                scenario,
                mode,
                work,
                definition,
                workspace,
                envelope,
                authority,
                progress_emitter,
                cancellation_event,
                recovering=recovering,
            )
        except DurableEscalationRequired:
            await self._escalate(authority, "durable-lane-escalation-required")
            raise self._execution_failed(scenario) from None
        async with authority.hold() as token:
            work = await self._store.record_workflow_result(
                token,
                workflow_result,
                occurred_at=self._clock(),
            )
        await self._recover_or_run_cleanup(work, scenario, workspace, authority)
        return workflow_result

    async def _validated_workspace(
        self,
        work: ScenarioWorkItem,
        scenario: ScenarioName,
        mode: ScenarioMode,
        authority: _ScenarioAuthority,
    ) -> Path:
        if (
            work.runtime_provenance_sha256 != self._runtime_provenance(mode)
            or work.strategy_sha256 != _strategy_sha256(scenario, mode)
            or work.semantic_config_sha256 != self._semantic_config_sha256
        ):
            if work.investigation_state is not ScenarioInvestigationState.RECORDED:
                await self._escalate(authority, "scenario-dependency-drift")
            raise self._execution_failed(scenario)
        if work.workspace_id != _workspace_id(work.scenario_request.investigation_id):
            if work.investigation_state is not ScenarioInvestigationState.RECORDED:
                await self._escalate(authority, "scenario-workspace-drift")
            raise self._execution_failed(scenario)
        workspace = self._workspace_root / work.workspace_id
        if workspace.is_symlink():
            if work.investigation_state is not ScenarioInvestigationState.RECORDED:
                await self._escalate(authority, "scenario-workspace-drift")
            raise self._execution_failed(scenario)
        workspace_missing = False
        try:
            resolved = workspace.resolve(strict=True)
            metadata = workspace.lstat()
        except FileNotFoundError:
            workspace_missing = True
            resolved = None
            metadata = None
        except OSError:
            resolved = None
            metadata = None
        if (
            workspace_missing
            and self._workspace_root_is_secure()
            and await self._pristine_workspace_repair_allowed(work)
        ):
            repair_candidate = True
            try:
                workspace.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError:
                repair_candidate = False
            if repair_candidate:
                try:
                    resolved = workspace.resolve(strict=True)
                    metadata = workspace.lstat()
                except OSError:
                    resolved = None
                    metadata = None
            else:
                resolved = None
                metadata = None
        if (
            resolved != workspace
            or metadata is None
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            if work.investigation_state is not ScenarioInvestigationState.RECORDED:
                await self._escalate(authority, "scenario-workspace-drift")
            raise self._execution_failed(scenario)
        return workspace

    def _workspace_root_is_secure(self) -> bool:
        try:
            resolved = self._workspace_root.resolve(strict=True)
            metadata = self._workspace_root.lstat()
        except OSError:
            return False
        return (
            resolved == self._workspace_root
            and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and not metadata.st_mode & 0o077
        )

    async def _pristine_workspace_repair_allowed(
        self,
        work: ScenarioWorkItem,
    ) -> bool:
        if (
            work.mutation_state is not ScenarioMutationState.NOT_STARTED
            or work.prepared_envelope_sha256 is not None
            or work.cleanup_manifest_sha256 is not None
            or work.scenario_result is not None
            or work.envelope_sha256 is not None
            or work.investigation_state is not ScenarioInvestigationState.NOT_STARTED
            or work.workflow_result is not None
            or work.cleanup_status is not CleanupStatus.NOT_REQUESTED
            or work.cleanup_failure_code is not None
            or work.recovery_failure_code is not None
        ):
            return False
        for lane in ScenarioLane:
            if (
                await self._store.get_lane_result(
                    work.scenario_request.investigation_id,
                    lane,
                )
                is not None
            ):
                return False
        return True

    async def _investigate_durably(
        self,
        scenario: ScenarioName,
        mode: ScenarioMode,
        work: ScenarioWorkItem,
        definition,
        workspace: Path,
        envelope,
        authority: _ScenarioAuthority,
        progress_emitter: ProgressEmitter | None,
        cancellation_event: asyncio.Event | None,
        *,
        recovering: bool,
    ) -> ScenarioWorkflowResult:
        expectation = _expectation(scenario)

        async def record_lane(lane: ScenarioLane, result) -> None:
            async with authority.hold() as token:
                await self._store.record_lane_result(
                    token,
                    lane,
                    result,
                    occurred_at=self._clock(),
                )

        fixed_executor = _FixedScenarioExecutor(
            scenario=scenario,
            workspace=workspace,
            expectation=expectation,
            progress_emitter=progress_emitter,
            lane_recorder=(record_lane if mode is ScenarioMode.COMPARE else None),
        )
        if mode is ScenarioMode.FIXED:
            return await self._run_lane(
                work,
                ScenarioLane.FIXED,
                DurableExecutionStrategy.FIXED,
                fixed_executor,
                envelope,
                cancellation_event,
                require_existing=False,
            )

        adaptive_executor = _AdaptiveScenarioExecutor(
            scenario=scenario,
            definition=definition,
            planner_factory=self._planner_factory,
            expectation=expectation,
            progress_emitter=progress_emitter,
            lane_recorder=(record_lane if mode is ScenarioMode.COMPARE else None),
        )
        if mode is ScenarioMode.ADAPTIVE:
            return await self._run_lane(
                work,
                ScenarioLane.ADAPTIVE,
                DurableExecutionStrategy.ADAPTIVE,
                adaptive_executor,
                envelope,
                cancellation_event,
                require_existing=recovering,
            )

        await self._run_lane(
            work,
            ScenarioLane.FIXED,
            DurableExecutionStrategy.FIXED,
            fixed_executor,
            envelope,
            cancellation_event,
            require_existing=False,
        )
        await self._run_lane(
            work,
            ScenarioLane.ADAPTIVE,
            DurableExecutionStrategy.ADAPTIVE,
            adaptive_executor,
            envelope,
            cancellation_event,
            require_existing=recovering,
        )
        baseline = await self._store.get_lane_result(
            work.scenario_request.investigation_id,
            ScenarioLane.FIXED,
        )
        adaptive = await self._store.get_lane_result(
            work.scenario_request.investigation_id,
            ScenarioLane.ADAPTIVE,
        )
        if baseline is None or adaptive is None:
            raise DurableEscalationRequired(work.scenario_request.investigation_id)
        digest = hashlib.sha256(
            canonical_json_value_bytes(
                {"run_id": work.scenario_request.run_id, "scenario": scenario.value}
            )
        ).hexdigest()[:20]
        short_name = _RECIPES[scenario].short_name
        return InvestigationComparisonRecord(
            schema_version=INVESTIGATION_COMPARISON_RECORD_VERSION,
            comparison_id=f"comparison-{short_name}-{digest}",
            case_id=f"case-{short_name}-{digest}",
            scenario=work.scenario_request.scenario,
            envelope_sha256=canonical_sha256(envelope),
            preregistered_expectation=expectation,
            baseline=baseline,
            adaptive=adaptive,
        )

    async def _run_lane(
        self,
        work: ScenarioWorkItem,
        lane: ScenarioLane,
        strategy: DurableExecutionStrategy,
        executor,
        envelope,
        cancellation_event: asyncio.Event | None,
        *,
        require_existing: bool,
    ) -> InvestigationReport:
        path = (
            self._workspace_root
            / work.workspace_id
            / f"runtime-{lane.value.lower()}.sqlite3"
        )
        try:
            path_metadata = path.lstat()
        except FileNotFoundError:
            path_metadata = None
        except OSError:
            raise DurableEscalationRequired(
                work.scenario_request.investigation_id
            ) from None
        if path_metadata is not None and (
            not stat.S_ISREG(path_metadata.st_mode)
            or path_metadata.st_uid != os.geteuid()
            or path_metadata.st_mode & 0o077
        ):
            raise DurableEscalationRequired(work.scenario_request.investigation_id)
        if require_existing and path_metadata is None:
            raise DurableEscalationRequired(work.scenario_request.investigation_id)
        try:
            store = SqliteDurableRuntimeStore(path)
            service = DurableInvestigationApplicationService(
                store,
                executor,
                strategy=strategy,
                owner_id=f"scenario-{lane.value.lower()}",
                semantic_config_sha256=self._semantic_config_sha256,
                max_provider_calls=(
                    0
                    if strategy is DurableExecutionStrategy.FIXED
                    else _PLANNER_MAX_CALLS
                ),
                max_estimated_cost_microunits=(
                    0
                    if strategy is DurableExecutionStrategy.FIXED
                    else _PLANNER_MAX_CALLS
                ),
                event_poll_interval=_POLL_SECONDS,
            )
            runs = await store.list_runs()
            if len(runs) > 1 or (require_existing and len(runs) != 1):
                raise DurableEscalationRequired(envelope.investigation_id)
            if runs and (
                runs[0].investigation_id != envelope.investigation_id
                or canonical_json_bytes(runs[0].envelope)
                != canonical_json_bytes(envelope)
                or await store.runtime_provenance_sha256(runs[0].investigation_id)
                != service.runtime_provenance_sha256
            ):
                raise DurableEscalationRequired(envelope.investigation_id)
        except asyncio.CancelledError:
            raise
        except DurableEscalationRequired:
            raise
        except Exception:
            raise DurableEscalationRequired(envelope.investigation_id) from None
        try:
            await service.start()
            await service.create(envelope)
            cursor = 0
            while True:
                if cancellation_event is not None and cancellation_event.is_set():
                    raise asyncio.CancelledError
                journal = await service.wait_for_events(
                    envelope.investigation_id,
                    after=cursor,
                    cancellation_event=cancellation_event,
                )
                cursor = journal.cursor
                if journal.terminal:
                    report = await service.get(envelope.investigation_id)
                    if report.status is not InvestigationStatus.COMPLETED:
                        raise DurableEscalationRequired(envelope.investigation_id)
                    return report
        except asyncio.CancelledError:
            raise
        except DurableEscalationRequired:
            raise
        except Exception:
            if require_existing:
                raise DurableEscalationRequired(envelope.investigation_id) from None
            raise
        finally:
            await service.aclose()

    async def _recover_or_run_cleanup(
        self,
        work: ScenarioWorkItem,
        scenario: ScenarioName,
        workspace: Path,
        authority: _ScenarioAuthority,
    ) -> None:
        if work.cleanup_status is CleanupStatus.PENDING:
            async with authority.hold() as token:
                await self._store.record_scenario_cleanup(
                    token,
                    CleanupStatus.FAILED,
                    occurred_at=self._clock(),
                    failure_code="cleanup-outcome-unknown",
                )
            return
        if work.cleanup_status in {CleanupStatus.SUCCEEDED, CleanupStatus.FAILED}:
            return
        if work.scenario_result is None or work.workflow_result is None:
            return
        runner = ScenarioRunner()
        definition = _definition(
            scenario,
            workspace,
            invoked_at=work.invoked_at,
            seed_sandbox=False,
        )
        cleanup_request = runner.build_cleanup_request(
            work.scenario_request,
            work.scenario_result,
        )
        async with authority.hold() as token:
            await self._store.record_scenario_cleanup(
                token,
                CleanupStatus.PENDING,
                occurred_at=self._clock(),
            )
        task = asyncio.create_task(
            asyncio.to_thread(runner.cleanup, cleanup_request, definition)
        )
        cancelled = False
        try:
            cleanup = await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
            cleanup = await task
        succeeded = (
            cleanup.disposition
            in {
                ScenarioCleanupDisposition.CLEANED,
                ScenarioCleanupDisposition.ALREADY_CLEAN,
            }
            and cleanup.remaining_count == 0
        )
        async with authority.hold() as token:
            await self._store.record_scenario_cleanup(
                token,
                CleanupStatus.SUCCEEDED if succeeded else CleanupStatus.FAILED,
                occurred_at=self._clock(),
                failure_code=None if succeeded else "cleanup-failed",
            )
        if cancelled:
            raise asyncio.CancelledError

    async def _escalate(
        self,
        authority: _ScenarioAuthority,
        failure_code: str,
    ) -> None:
        async with authority.hold() as token:
            await self._store.require_scenario_escalation(
                token,
                failure_code,
                occurred_at=self._clock(),
            )

    @staticmethod
    def _execution_failed(scenario: ScenarioName) -> ScenarioWorkflowError:
        return ScenarioWorkflowError(
            ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED,
            scenario=scenario,
        )


def re_full_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


__all__ = ["DurableScenarioWorkflow"]
