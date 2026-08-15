"""API-only Textual operator surface for canonical scenario investigations."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Awaitable
from contextlib import suppress
from typing import ClassVar, Protocol

from textual import events, on
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Select,
    Static,
    TabbedContent,
    TabPane,
)
from textual.worker import WorkerCancelled

from reconcile.contracts import (
    SCENARIO_LAUNCH_REQUEST_VERSION,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioOperationalStatus,
    ScenarioRunEvent,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunSnapshot,
)
from reconcile.interfaces.api_client import (
    InvalidRequestError,
    InvestigationApiClientError,
    InvestigationConflictError,
    InvestigationNotFoundError,
    RemoteInternalError,
    RemoteProtocolError,
    ServiceUnavailableError,
    TransportError,
)
from reconcile.interfaces.operator_api_client import (
    DEFAULT_OPERATOR_API_BASE_URL,
    LaunchOutcomeUnknownError,
    OperatorApiClient,
    StreamInterruptedError,
)
from reconcile.interfaces.tui_state import (
    ConnectionPhase,
    OperatorViewState,
    ViewStateProtocolError,
)


class _LaunchResult(Protocol):
    created: bool
    snapshot: ScenarioRunSnapshot


class _OperatorClient(Protocol):
    async def launch(self, request: ScenarioLaunchRequest) -> _LaunchResult: ...

    async def get_snapshot(
        self,
        investigation_id: str,
    ) -> ScenarioRunSnapshot: ...

    async def get_operational_status(
        self,
        investigation_id: str,
    ) -> ScenarioOperationalStatus: ...

    def events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
        max_reconnects: int = 3,
    ) -> AsyncIterator[ScenarioRunEvent]: ...

    async def aclose(self) -> None: ...


_TERMINAL_MESSAGE = "Terminal snapshot confirmed by the API."
_TERMINAL_LIFECYCLES = frozenset(
    {
        ScenarioRunLifecycle.COMPLETED,
        ScenarioRunLifecycle.FAILED,
        ScenarioRunLifecycle.CANCELLED,
    }
)


class ReconcileApp(App[None]):
    """Inspectable terminal client with no in-process investigation authority."""

    BINDINGS: ClassVar = [
        ("f5", "launch", "Launch"),
        ("f6", "attach", "Attach"),
        ("r", "reconnect", "Reconnect"),
        ("c", "copy_investigation_id", "Copy ID"),
        ("q", "quit", "Quit"),
    ]

    CSS = """
    Screen {
        background: $surface;
        color: $text;
    }

    #app-body {
        height: 1fr;
    }

    #product-title {
        height: 3;
        padding: 1 2;
        text-style: bold;
        background: $primary;
        color: white;
    }

    #command-bar {
        height: 7;
        padding: 0 1;
        border-bottom: solid $primary;
    }

    .command-row {
        height: 3;
        layout: horizontal;
    }

    .command-row Select {
        width: 22;
        margin-right: 1;
    }

    .command-row Input {
        width: 1fr;
        min-width: 12;
        margin-right: 1;
    }

    .command-row Button {
        width: 13;
        margin-right: 1;
    }

    #operator-message, #identity-strip {
        height: auto;
        min-height: 2;
        padding: 0 2;
    }

    #operator-message {
        border-bottom: solid $secondary;
    }

    #identity-strip {
        text-style: bold;
        border-bottom: solid $primary;
    }

    #workspace {
        height: 1fr;
    }

    .tab-scroll {
        height: 1fr;
        padding: 0 1 1 1;
    }

    .section {
        height: auto;
        min-height: 3;
        padding: 0 1;
        margin-top: 1;
        border: solid $primary;
    }

    #outcome-panel {
        margin-top: 0;
        border: heavy $primary;
        text-style: bold;
    }

    #timeline-panel, #evidence-panel, #comparison-panel {
        min-height: 8;
    }

    .narrow Header, .narrow Footer, .narrow #product-title {
        display: none;
    }

    .narrow #command-bar {
        height: 6;
        padding: 0;
    }

    .narrow .command-row Select {
        width: 14;
        margin-right: 0;
    }

    .narrow .command-row Button {
        width: 10;
        margin-right: 0;
    }

    .narrow #operator-message, .narrow #identity-strip {
        height: 1;
        min-height: 1;
        padding: 0 1;
    }
    """

    def __init__(
        self,
        *,
        api_base_url: str | None = None,
        client: _OperatorClient | None = None,
    ) -> None:
        super().__init__()
        self._api_base_url = api_base_url or os.environ.get(
            "RECONCILE_API_URL",
            DEFAULT_OPERATOR_API_BASE_URL,
        )
        self._client = client
        self._view_state = OperatorViewState.empty()
        self._operation_lock = asyncio.Lock()
        self._operation_pending = False
        self._operator_message = (
            "[READY] Choose a canonical scenario launch or attach by investigation ID."
        )

    @property
    def operator_view_state(self) -> OperatorViewState:
        """Expose the immutable API-derived view state for acceptance checks."""

        return self._view_state

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="app-body"):
            yield Static(
                "RECONCILE — EVIDENCE, DETERMINISTIC STATE, ACTION PERMISSION",
                id="product-title",
                markup=False,
            )
            with Vertical(id="command-bar"):
                with Horizontal(classes="command-row", id="launch-row"):
                    yield Select(
                        ((item.value, item) for item in ScenarioLaunchName),
                        value=ScenarioLaunchName.STORAGE,
                        allow_blank=False,
                        id="scenario-select",
                    )
                    yield Select(
                        ((item.value, item) for item in ScenarioRunMode),
                        value=ScenarioRunMode.FIXED,
                        allow_blank=False,
                        id="mode-select",
                    )
                    yield Input(
                        placeholder="launch ID (idempotency key)",
                        max_length=128,
                        id="launch-id",
                    )
                    yield Button("Launch [F5]", id="launch-button", variant="primary")
                with Horizontal(classes="command-row", id="attach-row"):
                    yield Input(
                        placeholder="investigation ID (selectable and copyable)",
                        max_length=128,
                        id="investigation-id",
                    )
                    yield Button("Attach [F6]", id="attach-button")
                    yield Button("Reconnect [R]", id="reconnect-button")
            yield Static(
                self._operator_message,
                id="operator-message",
                markup=False,
            )
            yield Static("API: NOT CONTACTED", id="identity-strip", markup=False)
            with TabbedContent(initial="summary-tab", id="workspace"):
                with TabPane("Summary", id="summary-tab"):
                    with VerticalScroll(classes="tab-scroll"):
                        yield Static(
                            id="outcome-panel", classes="section", markup=False
                        )
                        yield Static(
                            id="operations-panel", classes="section", markup=False
                        )
                        yield Static(
                            id="transport-panel", classes="section", markup=False
                        )
                        yield Static(
                            id="envelope-panel", classes="section", markup=False
                        )
                        yield Static(
                            id="advisory-panel", classes="section", markup=False
                        )
                        yield Static(
                            id="deterministic-panel",
                            classes="section",
                            markup=False,
                        )
                        yield Static(
                            id="actions-panel", classes="section", markup=False
                        )
                        yield Static(
                            id="missing-panel", classes="section", markup=False
                        )
                with TabPane("Timeline", id="timeline-tab"):
                    with VerticalScroll(classes="tab-scroll"):
                        yield Static(
                            id="timeline-panel", classes="section", markup=False
                        )
                with TabPane("Evidence", id="evidence-tab"):
                    with VerticalScroll(classes="tab-scroll"):
                        yield Static(
                            id="evidence-panel", classes="section", markup=False
                        )
                with TabPane("Compare", id="comparison-tab"):
                    with VerticalScroll(classes="tab-scroll"):
                        yield Static(
                            id="comparison-panel", classes="section", markup=False
                        )
        yield Footer()

    async def on_mount(self) -> None:
        self._set_narrow(self.size.width < 90)
        if self._client is None:
            try:
                self._client = OperatorApiClient(self._api_base_url)
            except InvestigationApiClientError:
                self._view_state = self._view_state.set_connection(
                    ConnectionPhase.REFUSED
                )
                self._operator_message = (
                    "[REFUSED] API URL is invalid. Use a loopback HTTP or HTTPS URL."
                )
        self._render_state()

    def on_resize(self, event: events.Resize) -> None:
        self._set_narrow(event.size.width < 90)

    def _set_narrow(self, narrow: bool) -> None:
        self.screen.set_class(narrow, "narrow")

    def _render_state(self) -> None:
        self.query_one("#operator-message", Static).update(self._operator_message)
        connection = " ".join(self._view_state.render_connection())
        identity = " | ".join(self._view_state.render_identity())
        self.query_one("#identity-strip", Static).update(f"{connection} | {identity}")
        for widget_id, content in (
            ("#outcome-panel", self._view_state.render_outcome()),
            ("#operations-panel", self._view_state.render_operations()),
            ("#transport-panel", self._view_state.render_transport()),
            ("#envelope-panel", self._view_state.render_envelope()),
            ("#advisory-panel", self._view_state.render_advisory()),
            ("#deterministic-panel", self._view_state.render_deterministic()),
            ("#actions-panel", self._view_state.render_actions()),
            ("#missing-panel", self._view_state.render_missing()),
            ("#timeline-panel", self._view_state.render_timeline()),
            ("#evidence-panel", self._view_state.render_evidence()),
            ("#comparison-panel", self._view_state.render_comparison()),
        ):
            self.query_one(widget_id, Static).update("\n".join(content))

    def _client_or_refuse(self) -> _OperatorClient | None:
        if self._client is None:
            self._view_state = self._view_state.set_connection(ConnectionPhase.REFUSED)
            self._operator_message = "[REFUSED] API client is unavailable."
            self._render_state()
            return None
        return self._client

    @on(Button.Pressed, "#launch-button")
    def _launch_pressed(self) -> None:
        self.action_launch()

    @on(Button.Pressed, "#attach-button")
    def _attach_pressed(self) -> None:
        self.action_attach()

    @on(Button.Pressed, "#reconnect-button")
    def _reconnect_pressed(self) -> None:
        self.action_reconnect()

    def action_launch(self) -> None:
        if not self._reserve_operation():
            return
        scenario = self.query_one("#scenario-select", Select).value
        mode = self.query_one("#mode-select", Select).value
        launch_id = self.query_one("#launch-id", Input).value
        self.run_worker(
            self._run_reserved(
                self._launch_and_watch(
                    scenario=scenario,
                    mode=mode,
                    launch_id=launch_id,
                )
            ),
            name="scenario-launch",
            group="scenario-session",
            exclusive=False,
            exit_on_error=False,
        )

    def action_attach(self) -> None:
        if not self._reserve_operation():
            return
        investigation_id = self.query_one("#investigation-id", Input).value
        self.run_worker(
            self._run_reserved(self._attach_and_watch(investigation_id)),
            name="scenario-attach",
            group="scenario-session",
            exclusive=False,
            exit_on_error=False,
        )

    def action_reconnect(self) -> None:
        if not self._reserve_operation():
            return
        snapshot = self._view_state.snapshot
        investigation_id = None if snapshot is None else snapshot.investigation_id
        self.run_worker(
            self._run_reserved(self._reconnect_and_watch(investigation_id)),
            name="scenario-reconnect",
            group="scenario-session",
            exclusive=False,
            exit_on_error=False,
        )

    def _reserve_operation(self) -> bool:
        if self._operation_pending:
            self._operator_message = (
                "[BUSY] Current operation remains active; no request was cancelled "
                "or submitted."
            )
            self._render_state()
            return False
        self._operation_pending = True
        return True

    async def _run_reserved(self, operation: Awaitable[None]) -> None:
        try:
            await operation
        finally:
            self._operation_pending = False

    def action_copy_investigation_id(self) -> None:
        snapshot = self._view_state.snapshot
        investigation_id = None if snapshot is None else snapshot.investigation_id
        if not investigation_id:
            investigation_id = self.query_one("#investigation-id", Input).value
        if not investigation_id:
            self._operator_message = "[COPY] No investigation ID is available."
        else:
            self.copy_to_clipboard(investigation_id)
            self._operator_message = "[COPY] Investigation ID copied exactly."
        self._render_state()

    async def _launch_and_watch(
        self,
        *,
        scenario: object,
        mode: object,
        launch_id: str,
    ) -> None:
        async with self._operation_lock:
            client = self._client_or_refuse()
            if client is None:
                return
            self._view_state = self._view_state.reset(
                connection_phase=ConnectionPhase.CONNECTING
            )
            self.query_one("#investigation-id", Input).value = ""
            try:
                request = ScenarioLaunchRequest(
                    schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
                    launch_id=launch_id,
                    scenario=scenario,
                    mode=mode,
                )
            except (TypeError, ValueError):
                self._view_state = self._view_state.set_connection(
                    ConnectionPhase.REFUSED
                )
                self._operator_message = (
                    "[REFUSED] Launch requires a bounded ID, scenario, and mode."
                )
                self._render_state()
                return

            self._view_state = self._view_state.set_connection(
                ConnectionPhase.CONNECTING
            )
            self._operator_message = "[CONNECTING] Submitting one idempotent launch."
            self._render_state()
            try:
                launched = await client.launch(request)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                self._show_client_failure(error, launch=True)
                return

            self._view_state = self._view_state.reset(
                connection_phase=ConnectionPhase.CONNECTING
            ).apply_snapshot(launched.snapshot)
            self.query_one(
                "#investigation-id", Input
            ).value = launched.snapshot.investigation_id
            self._operator_message = (
                "[ACCEPTED] New launch accepted; rebuilding the server timeline."
                if launched.created
                else "[REPLAY] Exact launch replay; rebuilding the server timeline."
            )
            self._render_state()
            await self._refresh_operational_status(
                client,
                launched.snapshot.investigation_id,
            )
            await self._watch(launched.snapshot.investigation_id, after=0)

    async def _attach_and_watch(self, investigation_id: str) -> None:
        async with self._operation_lock:
            client = self._client_or_refuse()
            if client is None:
                return
            self._view_state = self._view_state.reset(
                connection_phase=ConnectionPhase.CONNECTING
            )
            self._operator_message = "[CONNECTING] Attaching to the API snapshot."
            self._render_state()
            try:
                snapshot = await client.get_snapshot(investigation_id)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                self._show_client_failure(error)
                return

            self._view_state = self._view_state.reset(
                connection_phase=ConnectionPhase.CONNECTING
            ).apply_snapshot(snapshot)
            self._operator_message = (
                "[ATTACHED] Rebuilding the bounded timeline from cursor 0."
            )
            self._render_state()
            await self._refresh_operational_status(client, snapshot.investigation_id)
            await self._watch(snapshot.investigation_id, after=0)

    async def _reconnect_and_watch(self, investigation_id: str | None) -> None:
        async with self._operation_lock:
            client = self._client_or_refuse()
            if client is None:
                return
            if investigation_id is None:
                self._view_state = self._view_state.set_connection(
                    ConnectionPhase.REFUSED
                )
                self._operator_message = (
                    "[REFUSED] Launch or attach before reconnecting a stream."
                )
                self._render_state()
                return
            self._view_state = self._view_state.set_connection(
                ConnectionPhase.CONNECTING
            )
            self._operator_message = (
                f"[RECONNECTING] Last confirmed cursor {self._view_state.last_cursor}."
            )
            self._render_state()
            try:
                snapshot = await client.get_snapshot(investigation_id)
                self._view_state = self._view_state.apply_snapshot(snapshot)
            except asyncio.CancelledError:
                raise
            except ViewStateProtocolError:
                self._show_protocol_failure()
                return
            except Exception as error:
                self._show_client_failure(error)
                return
            await self._refresh_operational_status(client, investigation_id)
            await self._watch(
                investigation_id,
                after=self._view_state.last_cursor,
            )

    async def _watch(self, investigation_id: str, *, after: int) -> None:
        client = self._client_or_refuse()
        if client is None:
            return
        self._view_state = self._view_state.set_connection(ConnectionPhase.LIVE)
        self._operator_message = f"[LIVE] Streaming after cursor {after}."
        self._render_state()
        try:
            async for event in client.events(
                investigation_id,
                after=after,
                max_reconnects=0,
            ):
                self._view_state = self._view_state.ingest(event)
                self._render_state()
            snapshot = await client.get_snapshot(investigation_id)
            self._view_state = self._view_state.apply_snapshot(snapshot).set_connection(
                ConnectionPhase.LIVE
            )
            await self._refresh_operational_status(client, investigation_id)
        except asyncio.CancelledError:
            raise
        except ViewStateProtocolError:
            self._show_protocol_failure()
            return
        except Exception as error:
            self._show_client_failure(error, stream=True)
            return

        snapshot = self._view_state.snapshot
        if (
            snapshot is not None
            and snapshot.lifecycle in _TERMINAL_LIFECYCLES
            and self._view_state.timeline_complete
        ):
            self._operator_message = _TERMINAL_MESSAGE
        elif snapshot is not None and snapshot.lifecycle in _TERMINAL_LIFECYCLES:
            self._show_protocol_failure()
            return
        else:
            self._operator_message = (
                "[LIVE] Snapshot refreshed; decision remains pending."
            )
        self._render_state()

    async def _refresh_operational_status(
        self,
        client: _OperatorClient,
        investigation_id: str,
    ) -> None:
        try:
            status = await client.get_operational_status(investigation_id)
            self._view_state = self._view_state.apply_operational_status(status)
        except asyncio.CancelledError:
            raise
        except (RemoteProtocolError, ViewStateProtocolError):
            self._view_state = self._view_state.mark_operational_status_unavailable(
                invalid=True
            )
        except Exception:
            self._view_state = self._view_state.mark_operational_status_unavailable()
        self._render_state()

    def _show_protocol_failure(self) -> None:
        self._view_state = self._view_state.set_connection(
            ConnectionPhase.PROTOCOL_ERROR
        )
        self._operator_message = "[INVALID SERVER RESPONSE] Last good API state retained; reconnect is explicit."
        self._render_state()

    def _show_client_failure(
        self,
        error: Exception,
        *,
        launch: bool = False,
        stream: bool = False,
    ) -> None:
        if isinstance(error, RemoteProtocolError):
            self._show_protocol_failure()
            return
        if isinstance(error, LaunchOutcomeUnknownError):
            phase = ConnectionPhase.DISCONNECTED
            message = (
                "[LAUNCH OUTCOME UNKNOWN] No automatic retry. Exact replay of the same "
                "launch ID is available."
            )
        elif isinstance(error, StreamInterruptedError) or (
            stream and isinstance(error, TransportError)
        ):
            phase = ConnectionPhase.DISCONNECTED
            message = (
                "[STREAM INTERRUPTED] Last confirmed cursor "
                f"{self._view_state.last_cursor}; press R to reconnect."
            )
        elif isinstance(error, InvestigationConflictError):
            phase = ConnectionPhase.REFUSED
            message = (
                "[REQUEST CONFLICT] The launch ID is already bound; attach or use the "
                "exact original request."
            )
        elif isinstance(error, InvestigationNotFoundError):
            phase = ConnectionPhase.REFUSED
            message = "[NOT FOUND] The process-lifetime scenario run is unavailable."
        elif isinstance(error, ServiceUnavailableError):
            phase = ConnectionPhase.REFUSED
            message = (
                "[SERVICE UNAVAILABLE] Request refused; inspect API availability and "
                "retry explicitly."
            )
        elif isinstance(error, InvalidRequestError):
            phase = ConnectionPhase.REFUSED
            message = "[REFUSED] The API request is invalid."
        elif isinstance(error, RemoteInternalError):
            phase = ConnectionPhase.REFUSED
            message = "[REMOTE FAILURE] The API could not complete the request."
        elif isinstance(error, TransportError):
            phase = ConnectionPhase.DISCONNECTED
            message = "[API UNREACHABLE] Check the configured API and retry explicitly."
        elif isinstance(error, InvestigationApiClientError):
            phase = ConnectionPhase.REFUSED
            message = "[REQUEST REFUSED] The API request could not be completed."
        else:
            phase = ConnectionPhase.REFUSED
            message = "[LOCAL UI FAILURE] No server result was inferred."
        if launch and isinstance(error, TransportError):
            message = (
                "[LAUNCH OUTCOME UNKNOWN] No automatic retry. Exact replay of the same "
                "launch ID is available."
            )
        self._view_state = self._view_state.set_connection(phase)
        self._operator_message = message
        self._render_state()

    async def on_unmount(self) -> None:
        self.workers.cancel_all()
        try:
            with suppress(WorkerCancelled):
                await self.workers.wait_for_complete()
        finally:
            self._view_state = self._view_state.set_connection(ConnectionPhase.CLOSED)
            if self._client is not None:
                await self._client.aclose()


def main() -> None:
    """Run the configured API-only terminal client."""

    ReconcileApp().run()
