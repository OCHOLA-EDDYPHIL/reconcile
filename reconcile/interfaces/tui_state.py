"""Pure API-derived state and plain terminal projections for the TUI."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from reconcile.contracts import (
    AdvisoryTurnEventPayload,
    EnvelopeSummaryEventPayload,
    EvidenceDisposition,
    OperatorEvidenceDecisionEventPayload,
    ProbeRequestDisposition,
    ProbeRequestEventPayload,
    ProbeResultEventPayload,
    SanitizedComparisonRun,
    ScenarioLifecycleEventPayload,
    ScenarioOperationalStatus,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunSnapshot,
    TerminalStateEventPayload,
    canonical_json_bytes,
    decode_contract,
)


class ConnectionPhase(StrEnum):
    """Operator-visible state of the API connection."""

    IDLE = "IDLE"
    CONNECTING = "CONNECTING"
    LIVE = "LIVE"
    DISCONNECTED = "DISCONNECTED"
    REFUSED = "REFUSED"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    CLOSED = "CLOSED"


class OperationalStatusAvailability(StrEnum):
    """Operator-visible freshness of the independent v2 status projection."""

    PENDING = "PENDING"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID = "INVALID"


class ViewStateProtocolErrorCode(StrEnum):
    """Stable fail-closed reasons for rejected API-derived state."""

    INVALID_SNAPSHOT = "invalid_snapshot"
    SNAPSHOT_IDENTITY = "snapshot_identity"
    SNAPSHOT_CURSOR_REGRESSION = "snapshot_cursor_regression"
    SNAPSHOT_LIFECYCLE_REGRESSION = "snapshot_lifecycle_regression"
    SNAPSHOT_DIVERGENCE = "snapshot_divergence"
    INVALID_EVENT = "invalid_event"
    EVENT_IDENTITY = "event_identity"
    DIVERGENT_DUPLICATE = "divergent_duplicate"
    EVENT_GAP = "event_gap"
    INVALID_OPERATIONAL_STATUS = "invalid_operational_status"
    OPERATIONAL_STATUS_IDENTITY = "operational_status_identity"
    OPERATIONAL_STATUS_REVISION_REGRESSION = "operational_status_revision_regression"
    OPERATIONAL_STATUS_DIVERGENCE = "operational_status_divergence"


class ViewStateProtocolError(ValueError):
    """An API projection could not be applied without losing integrity."""

    def __init__(self, code: ViewStateProtocolErrorCode) -> None:
        self.code = code
        super().__init__(f"operator view state rejected {code.value}")


@dataclass(frozen=True, slots=True)
class RenderedSections:
    """Plain text sections whose semantics do not depend on color."""

    connection: tuple[str, ...]
    identity: tuple[str, ...]
    outcome: tuple[str, ...]
    operations: tuple[str, ...]
    transport: tuple[str, ...]
    envelope: tuple[str, ...]
    advisory: tuple[str, ...]
    timeline: tuple[str, ...]
    evidence: tuple[str, ...]
    deterministic: tuple[str, ...]
    actions: tuple[str, ...]
    missing: tuple[str, ...]
    comparison: tuple[str, ...]


def _joined(values: tuple[str, ...]) -> str:
    return ",".join(values) if values else "NONE"


def _optional(value: object | None) -> str:
    if value is None:
        return "NONE"
    if isinstance(value, StrEnum):
        return value.value
    return str(value)


def _snapshot_identity(snapshot: ScenarioRunSnapshot) -> tuple[object, ...]:
    return (
        snapshot.launch_id,
        snapshot.investigation_id,
        snapshot.scenario,
        snapshot.mode,
    )


def _operational_status_identity(
    status: ScenarioOperationalStatus,
) -> tuple[object, ...]:
    return (
        status.launch_id,
        status.investigation_id,
        status.scenario,
        status.mode,
    )


@dataclass(frozen=True, slots=True)
class OperatorViewState:
    """Immutable reducer state sourced only from operator API contracts."""

    connection_phase: ConnectionPhase = ConnectionPhase.IDLE
    snapshot: ScenarioRunSnapshot | None = None
    event_bytes_by_cursor: tuple[tuple[int, bytes], ...] = ()
    operational_status: ScenarioOperationalStatus | None = None
    operational_status_availability: OperationalStatusAvailability = (
        OperationalStatusAvailability.PENDING
    )

    @classmethod
    def empty(cls) -> OperatorViewState:
        """Return a state with no locally retained investigation."""

        return cls()

    def reset(
        self,
        *,
        connection_phase: ConnectionPhase = ConnectionPhase.CONNECTING,
    ) -> OperatorViewState:
        """Discard one local projection before launch or attach."""

        if type(connection_phase) is not ConnectionPhase:
            raise TypeError("connection phase must be exact")
        return type(self)(connection_phase=connection_phase)

    def set_connection(self, phase: ConnectionPhase) -> OperatorViewState:
        """Update connection presentation without changing investigation data."""

        if type(phase) is not ConnectionPhase:
            raise TypeError("connection phase must be exact")
        return replace(self, connection_phase=phase)

    @property
    def last_cursor(self) -> int:
        """Return the greatest contiguous cursor retained locally."""

        if not self.event_bytes_by_cursor:
            return 0
        return self.event_bytes_by_cursor[-1][0]

    @property
    def timeline_complete(self) -> bool:
        """Whether the local journal reaches the authoritative snapshot cursor."""

        return self.snapshot is not None and (
            self.last_cursor == self.snapshot.event_cursor
        )

    @property
    def events(self) -> tuple[ScenarioRunEvent, ...]:
        """Decode the exact canonical event bytes in cursor order."""

        return tuple(
            decode_contract(payload, ScenarioRunEvent)
            for _, payload in self.event_bytes_by_cursor
        )

    def event_at(self, cursor: int) -> ScenarioRunEvent | None:
        """Return one retained event by its one-based cursor."""

        if type(cursor) is not int or cursor < 1:
            raise ValueError("event cursor must be a positive integer")
        if cursor > self.last_cursor:
            return None
        return decode_contract(
            self.event_bytes_by_cursor[cursor - 1][1],
            ScenarioRunEvent,
        )

    def apply_snapshot(self, snapshot: ScenarioRunSnapshot) -> OperatorViewState:
        """Accept one authoritative snapshot without deriving missing decisions."""

        if type(snapshot) is not ScenarioRunSnapshot:
            raise ViewStateProtocolError(
                ViewStateProtocolErrorCode.INVALID_SNAPSHOT
            ) from None
        snapshot = decode_contract(canonical_json_bytes(snapshot), ScenarioRunSnapshot)
        previous = self.snapshot
        if previous is not None and _snapshot_identity(snapshot) != (
            _snapshot_identity(previous)
        ):
            raise ViewStateProtocolError(
                ViewStateProtocolErrorCode.SNAPSHOT_IDENTITY
            ) from None
        if snapshot.event_cursor < max(
            self.last_cursor,
            0 if previous is None else previous.event_cursor,
        ):
            raise ViewStateProtocolError(
                ViewStateProtocolErrorCode.SNAPSHOT_CURSOR_REGRESSION
            ) from None
        if previous is not None:
            if snapshot.accepted_at != previous.accepted_at:
                raise ViewStateProtocolError(
                    ViewStateProtocolErrorCode.SNAPSHOT_DIVERGENCE
                ) from None
            lifecycle_rank = {
                ScenarioRunLifecycle.ACCEPTED: 0,
                ScenarioRunLifecycle.RUNNING: 1,
                ScenarioRunLifecycle.COMPLETED: 2,
                ScenarioRunLifecycle.FAILED: 2,
                ScenarioRunLifecycle.CANCELLED: 2,
            }
            terminal = {
                ScenarioRunLifecycle.COMPLETED,
                ScenarioRunLifecycle.FAILED,
                ScenarioRunLifecycle.CANCELLED,
            }
            if lifecycle_rank[snapshot.lifecycle] < lifecycle_rank[previous.lifecycle]:
                raise ViewStateProtocolError(
                    ViewStateProtocolErrorCode.SNAPSHOT_LIFECYCLE_REGRESSION
                ) from None
            if previous.lifecycle in terminal and snapshot != previous:
                raise ViewStateProtocolError(
                    ViewStateProtocolErrorCode.SNAPSHOT_DIVERGENCE
                ) from None
            if snapshot.event_cursor == previous.event_cursor and snapshot != previous:
                raise ViewStateProtocolError(
                    ViewStateProtocolErrorCode.SNAPSHOT_DIVERGENCE
                ) from None
            if (
                previous.envelope_summary is not None
                and snapshot.envelope_summary != previous.envelope_summary
            ):
                raise ViewStateProtocolError(
                    ViewStateProtocolErrorCode.SNAPSHOT_DIVERGENCE
                ) from None
        return replace(self, snapshot=snapshot)

    def apply_operational_status(
        self,
        status: ScenarioOperationalStatus,
    ) -> OperatorViewState:
        """Accept one identity-bound, monotonic v2 operational projection."""

        if type(status) is not ScenarioOperationalStatus:
            raise ViewStateProtocolError(
                ViewStateProtocolErrorCode.INVALID_OPERATIONAL_STATUS
            ) from None
        status = decode_contract(
            canonical_json_bytes(status),
            ScenarioOperationalStatus,
        )
        snapshot = self.snapshot
        if snapshot is None or _operational_status_identity(status) != (
            _snapshot_identity(snapshot)
        ):
            raise ViewStateProtocolError(
                ViewStateProtocolErrorCode.OPERATIONAL_STATUS_IDENTITY
            ) from None

        previous = self.operational_status
        if previous is not None:
            if _operational_status_identity(status) != (
                _operational_status_identity(previous)
            ):
                raise ViewStateProtocolError(
                    ViewStateProtocolErrorCode.OPERATIONAL_STATUS_IDENTITY
                ) from None
            if status.revision < previous.revision:
                raise ViewStateProtocolError(
                    ViewStateProtocolErrorCode.OPERATIONAL_STATUS_REVISION_REGRESSION
                ) from None
            if status.revision == previous.revision and status != previous:
                raise ViewStateProtocolError(
                    ViewStateProtocolErrorCode.OPERATIONAL_STATUS_DIVERGENCE
                ) from None
        return replace(
            self,
            operational_status=status,
            operational_status_availability=(OperationalStatusAvailability.AVAILABLE),
        )

    def mark_operational_status_unavailable(
        self,
        *,
        invalid: bool = False,
    ) -> OperatorViewState:
        """Retain all confirmed projections while making a v2 failure visible."""

        if type(invalid) is not bool:
            raise TypeError("invalid marker must be exact")
        availability = (
            OperationalStatusAvailability.INVALID
            if invalid
            else OperationalStatusAvailability.UNAVAILABLE
        )
        return replace(self, operational_status_availability=availability)

    def ingest(self, event: ScenarioRunEvent) -> OperatorViewState:
        """Append one contiguous event or ignore one exact replay."""

        if type(event) is not ScenarioRunEvent:
            raise ViewStateProtocolError(
                ViewStateProtocolErrorCode.INVALID_EVENT
            ) from None
        if self.snapshot is None or (
            event.investigation_id != self.snapshot.investigation_id
        ):
            raise ViewStateProtocolError(
                ViewStateProtocolErrorCode.EVENT_IDENTITY
            ) from None

        payload = canonical_json_bytes(event)
        if event.cursor <= self.last_cursor:
            retained = self.event_bytes_by_cursor[event.cursor - 1][1]
            if retained == payload:
                return self
            raise ViewStateProtocolError(
                ViewStateProtocolErrorCode.DIVERGENT_DUPLICATE
            ) from None
        if event.cursor != self.last_cursor + 1:
            raise ViewStateProtocolError(ViewStateProtocolErrorCode.EVENT_GAP) from None
        return replace(
            self,
            event_bytes_by_cursor=(
                *self.event_bytes_by_cursor,
                (event.cursor, payload),
            ),
        )

    def render_connection(self) -> tuple[str, ...]:
        return (f"API CONNECTION: {self.connection_phase.value}",)

    def render_identity(self) -> tuple[str, ...]:
        if self.snapshot is None:
            return ("RUN: NONE",)
        completeness = "COMPLETE" if self.timeline_complete else "INCOMPLETE"
        return (
            f"RUN: {self.snapshot.scenario.value} / {self.snapshot.mode.value}",
            f"LIFECYCLE: {self.snapshot.lifecycle.value}",
            f"INVESTIGATION ID: {self.snapshot.investigation_id}",
            f"LAUNCH ID: {self.snapshot.launch_id}",
            (
                "TIMELINE: "
                f"{self.last_cursor}/{self.snapshot.event_cursor} {completeness}"
            ),
        )

    def render_transport(self) -> tuple[str, ...]:
        summary = None if self.snapshot is None else self.snapshot.envelope_summary
        if summary is None:
            return ("MUTATION TRANSPORT: PENDING OR UNAVAILABLE",)
        return (
            f"MUTATION TRANSPORT: {summary.ambiguity_kind.value}",
            f"TARGET KIND: {summary.target_kind}",
            f"INVOKED AT: {summary.invoked_at.isoformat()}",
            f"AMBIGUITY OBSERVED AT: {summary.ambiguity_observed_at.isoformat()}",
        )

    def render_operations(self) -> tuple[str, ...]:
        availability = self.operational_status_availability
        if availability is OperationalStatusAvailability.PENDING:
            header = "OPERATIONAL STATUS: PENDING"
        elif availability is OperationalStatusAvailability.AVAILABLE:
            header = "OPERATIONAL STATUS: AVAILABLE"
        elif availability is OperationalStatusAvailability.INVALID:
            header = "OPERATIONAL STATUS: INVALID - V1 STATE RETAINED"
        else:
            header = "OPERATIONAL STATUS: UNAVAILABLE - V1 STATE RETAINED"

        status = self.operational_status
        if status is None:
            return (
                header,
                "MUTATION: UNAVAILABLE",
                "INVESTIGATION: UNAVAILABLE",
                "CLEANUP: UNAVAILABLE",
                "HUMAN ESCALATION: UNKNOWN",
            )
        return (
            header,
            f"OPERATIONS REVISION: {status.revision}",
            f"MUTATION: {status.mutation_state.value}",
            f"INVESTIGATION: {status.investigation_state.value}",
            f"CLEANUP: {status.cleanup_state.value}",
            f"HUMAN ESCALATION: {status.recovery_state.value}",
        )

    def render_outcome(self) -> tuple[str, ...]:
        """Return a compact authoritative result for the initial viewport."""

        deterministic = self.render_deterministic()[0]
        report = None if self.snapshot is None else self.snapshot.report
        if report is None:
            return (
                deterministic,
                self.render_actions()[0],
                self.render_missing()[0],
            )

        allowed = tuple(
            gate.requested_action.value for gate in report.action_gate if gate.allowed
        )
        denied = tuple(
            gate.requested_action.value
            for gate in report.action_gate
            if not gate.allowed
        )
        if report.missing_evidence:
            missing_effects = tuple(
                effect_id
                for item in report.missing_evidence
                for effect_id in item.effect_ids
            )
            missing = (
                f"MISSING EVIDENCE: ITEMS={len(report.missing_evidence)} "
                f"EFFECTS={_joined(missing_effects)}"
            )
        else:
            missing = "MISSING EVIDENCE: NONE"
        return (
            deterministic,
            (f"ACTION PERMISSION: ALLOWED={_joined(allowed)} DENIED={_joined(denied)}"),
            missing,
        )

    def render_envelope(self) -> tuple[str, ...]:
        summary = None if self.snapshot is None else self.snapshot.envelope_summary
        if summary is None:
            return ("EXECUTION ENVELOPE: PENDING OR UNAVAILABLE",)
        effects = tuple(
            (f"EXPECTED EFFECT: {effect.effect_id} scope={effect.commit_scope}")
            for effect in summary.expected_effects
        )
        capabilities = tuple(
            f"READ CAPABILITY: {item.name}@{item.version}"
            for item in summary.enabled_capabilities
        )
        budget = summary.evidence_budget
        return (
            f"ENVELOPE SHA256: {summary.envelope_sha256}",
            *effects,
            *capabilities,
            (
                "EVIDENCE BUDGET: "
                f"probes={budget.max_probes} elapsed_ms={budget.max_elapsed_ms} "
                f"bytes={budget.max_total_result_bytes} cost={budget.max_cost_units}"
            ),
        )

    def render_advisory(self) -> tuple[str, ...]:
        if self.snapshot is None:
            return ("ADVISORY: NO RUN",)
        if self.snapshot.mode is ScenarioRunMode.FIXED:
            return ("ADVISORY: NOT USED - FIXED STRATEGY",)
        turns = tuple(
            event.payload.turn
            for event in self.events
            if event.type is ScenarioRunEventType.ADVISORY_TURN
            and type(event.payload) is AdvisoryTurnEventPayload
        )
        if not turns:
            if self.snapshot.failure_category is not None:
                return (
                    "ADVISORY: UNAVAILABLE - RUN FAILED: "
                    f"{self.snapshot.failure_category.value.upper()}",
                )
            return ("ADVISORY: PENDING",)
        return tuple(
            (
                f"ADVISORY TURN: {turn.turn_sequence} phase={turn.phase.value} "
                f"status={turn.status.value} proposals={turn.proposal_count} "
                f"selected={turn.selected_proposal_count} "
                f"failure={_optional(turn.failure_category)}"
            )
            for turn in turns
        )

    @staticmethod
    def _render_event(event: ScenarioRunEvent) -> str:
        payload = event.payload
        prefix = f"CURSOR {event.cursor}"
        if type(payload) is ScenarioLifecycleEventPayload:
            return f"{prefix} LIFECYCLE: {payload.lifecycle.value}"
        if type(payload) is EnvelopeSummaryEventPayload:
            return f"{prefix} EXECUTION ENVELOPE: AVAILABLE"
        if type(payload) is AdvisoryTurnEventPayload:
            turn = payload.turn
            return (
                f"{prefix} ADVISORY TURN: {turn.turn_sequence} "
                f"{turn.phase.value} {turn.status.value}"
            )
        if type(payload) is ProbeRequestEventPayload:
            request = payload.request
            marker = (
                "PROBE REQUEST SELECTED"
                if request.disposition is ProbeRequestDisposition.SELECTED
                else "PROBE REQUEST DENIED"
            )
            return (
                f"{prefix} {marker}: lane={payload.strategy.value} "
                f"disposition={request.disposition.value.upper()} "
                f"capability={request.capability_name}@{request.capability_version} "
                f"request={request.request_sha256} "
                f"effects={_joined(request.relevant_effect_ids)}"
            )
        if type(payload) is ProbeResultEventPayload:
            probe = payload.probe
            return (
                f"{prefix} PROBE RESULT: lane={payload.strategy.value} "
                f"outcome={probe.outcome.value} stop={probe.stop_reason} "
                f"evidence={_joined(probe.evidence_ids)}"
            )
        if type(payload) is OperatorEvidenceDecisionEventPayload:
            decision = payload.decision
            marker = {
                EvidenceDisposition.ADMITTED: "EVIDENCE ADMITTED",
                EvidenceDisposition.WEAK: "EVIDENCE WEAK",
                EvidenceDisposition.REJECTED: "EVIDENCE REJECTED",
            }[decision.disposition]
            return (
                f"{prefix} {marker}: lane={payload.strategy.value} "
                f"id={decision.evidence_id} reason={decision.reason.value}"
            )
        if type(payload) is TerminalStateEventPayload:
            terminal = payload.terminal
            return (
                f"{prefix} TERMINAL: lifecycle={terminal.lifecycle.value} "
                f"result={terminal.result_kind.value} "
                f"failure={_optional(terminal.failure_category)}"
            )
        raise TypeError("scenario event payload is unsupported")

    def render_timeline(self) -> tuple[str, ...]:
        if not self.event_bytes_by_cursor:
            return ("TIMELINE EVENT: NONE",)
        return tuple(self._render_event(event) for event in self.events)

    def render_evidence(self) -> tuple[str, ...]:
        report = None if self.snapshot is None else self.snapshot.report
        if report is None:
            if self.snapshot is None:
                return ("TARGET EVIDENCE: NO RUN",)
            if self.snapshot.mode is ScenarioRunMode.COMPARE:
                return ("TARGET EVIDENCE: SEE FIXED AND ADAPTIVE TIMELINE LANES",)
            if self.snapshot.lifecycle in {
                ScenarioRunLifecycle.ACCEPTED,
                ScenarioRunLifecycle.RUNNING,
            }:
                return ("TARGET EVIDENCE: AWAITING AUTHORITATIVE SNAPSHOT",)
            return (f"TARGET EVIDENCE: UNAVAILABLE - {self.snapshot.lifecycle.value}",)
        if not report.evidence:
            return ("TARGET EVIDENCE: NONE",)
        lines: list[str] = []
        for item in report.evidence:
            marker = {
                EvidenceDisposition.ADMITTED: "TARGET EVIDENCE ADMITTED",
                EvidenceDisposition.WEAK: "TARGET EVIDENCE WEAK",
                EvidenceDisposition.REJECTED: "TARGET EVIDENCE REJECTED",
            }[item.disposition]
            assertions = tuple(
                f"{assertion.effect_id}:{assertion.state.value}"
                for assertion in item.effect_assertions
            )
            capability = (
                "NONE"
                if item.capability_name is None
                else f"{item.capability_name}@{item.capability_version}"
            )
            lines.append(
                f"{marker}: id={item.evidence_id} capability={capability} "
                f"reason={item.reason.value} authority={_optional(item.authority)} "
                f"operation={_optional(item.operation_status)} "
                f"effects={_joined(assertions)}"
            )
        return tuple(lines)

    def render_deterministic(self) -> tuple[str, ...]:
        if self.snapshot is None:
            return ("DETERMINISTIC DECISION: NO RUN",)
        if self.snapshot.lifecycle in {
            ScenarioRunLifecycle.ACCEPTED,
            ScenarioRunLifecycle.RUNNING,
        }:
            return ("DETERMINISTIC DECISION: PENDING",)
        if self.snapshot.lifecycle is ScenarioRunLifecycle.FAILED:
            return (
                "DETERMINISTIC DECISION: UNAVAILABLE - RUN FAILED: "
                f"{self.snapshot.failure_category.value.upper()}",  # type: ignore[union-attr]
            )
        if self.snapshot.lifecycle is ScenarioRunLifecycle.CANCELLED:
            return ("DETERMINISTIC DECISION: UNAVAILABLE - RUN CANCELLED",)
        if self.snapshot.mode is ScenarioRunMode.COMPARE:
            return (
                "DETERMINISTIC DECISION: NO OVERALL CLASSIFICATION - "
                "NEUTRAL COMPARISON",
            )

        report = self.snapshot.report
        if report is None or report.classification is None or report.proof is None:
            raise TypeError("completed report snapshot is incomplete")
        lines = [
            f"DETERMINISTIC CLASSIFICATION: {report.classification.value}",
            (
                "DETERMINISTIC PROOF: "
                f"operation={_optional(report.proof.operation_status)} "
                f"conflicting_authority={str(report.proof.conflicting_authority).upper()}"
            ),
        ]
        lines.extend(
            (
                f"PROOF EFFECT: {finding.effect_id} "
                f"scope={finding.commit_scope} state={finding.state.value} "
                f"evidence={_joined(finding.evidence_ids)}"
            )
            for finding in report.proof.effect_findings
        )
        return tuple(lines)

    def render_actions(self) -> tuple[str, ...]:
        if self.snapshot is None:
            return ("ACTION PERMISSION: NO RUN",)
        report = self.snapshot.report
        if report is None:
            if self.snapshot.mode is ScenarioRunMode.COMPARE:
                return ("ACTION PERMISSION: NOT APPLICABLE - NEUTRAL COMPARISON",)
            if self.snapshot.lifecycle in {
                ScenarioRunLifecycle.ACCEPTED,
                ScenarioRunLifecycle.RUNNING,
            }:
                return ("ACTION PERMISSION: PENDING",)
            return (
                f"ACTION PERMISSION: UNAVAILABLE - {self.snapshot.lifecycle.value}",
            )
        return tuple(
            (
                f"ACTION {gate.requested_action.value}: "
                f"{'ALLOWED' if gate.allowed else 'DENIED'} "
                f"reason={gate.reason.value} "
                f"escalation_required={str(gate.escalation_required).upper()}"
            )
            for gate in report.action_gate
        )

    def render_missing(self) -> tuple[str, ...]:
        if self.snapshot is None:
            return ("MISSING EVIDENCE: NO RUN",)
        report = self.snapshot.report
        if report is None:
            if self.snapshot.mode is ScenarioRunMode.COMPARE:
                return ("MISSING EVIDENCE: NOT APPLICABLE - NEUTRAL COMPARISON",)
            if self.snapshot.lifecycle in {
                ScenarioRunLifecycle.ACCEPTED,
                ScenarioRunLifecycle.RUNNING,
            }:
                return ("MISSING EVIDENCE: DECISION PENDING",)
            return (f"MISSING EVIDENCE: UNAVAILABLE - {self.snapshot.lifecycle.value}",)
        if not report.missing_evidence:
            return ("MISSING EVIDENCE: NONE",)
        return tuple(
            f"MISSING EVIDENCE: effects={_joined(item.effect_ids)} reason={item.reason}"
            for item in report.missing_evidence
        )

    @staticmethod
    def _render_comparison_lane(run: SanitizedComparisonRun) -> tuple[str, ...]:
        completeness = run.explanation_completeness
        model = run.model_usage
        return (
            f"COMPARISON LANE: {run.strategy_kind.value}",
            f"COMPARISON CLASSIFICATION: {run.classification.value}",
            (
                "COMPARISON PROBES: "
                f"planned={run.planned_probe_count} executed={run.executed_probe_count} "
                f"unsupported={run.unsupported_probe_count} "
                f"unnecessary={run.unnecessary_probe_count} "
                f"duplicate={run.duplicate_probe_count}"
            ),
            (
                "COMPARISON CONTROLLER: "
                f"cost={run.controller_cost_units_used} "
                f"bytes={run.controller_result_bytes_acquired} "
                f"elapsed_ms={run.total_elapsed_ms} "
                "sufficient_ms="
                f"{_optional(run.time_to_sufficient_evidence_ms)} "
                f"stop={run.stop_reason}"
            ),
            (
                "COMPARISON EXPLANATION: "
                f"complete={str(completeness.complete).upper()} "
                f"valid={completeness.valid_evidence_citation_count} "
                f"missing={completeness.missing_evidence_citation_count}"
            ),
            (
                "COMPARISON MODEL USAGE: "
                f"status={model.status.value} provider={_optional(model.provider_name)} "
                f"model={_optional(model.model_name)} calls={model.model_call_count} "
                f"input_tokens={_optional(model.input_token_count)} "
                f"output_tokens={_optional(model.output_token_count)} "
                f"total_tokens={_optional(model.total_token_count)}"
            ),
        )

    def render_comparison(self) -> tuple[str, ...]:
        if self.snapshot is None:
            return ("COMPARISON: NO RUN",)
        if self.snapshot.mode is not ScenarioRunMode.COMPARE:
            return (
                f"COMPARISON: NOT USED - {self.snapshot.mode.value.upper()} STRATEGY",
            )
        comparison = self.snapshot.comparison
        if comparison is None:
            if self.snapshot.lifecycle is ScenarioRunLifecycle.FAILED:
                return (
                    "COMPARISON: UNAVAILABLE - RUN FAILED: "
                    f"{self.snapshot.failure_category.value.upper()}",  # type: ignore[union-attr]
                )
            if self.snapshot.lifecycle is ScenarioRunLifecycle.CANCELLED:
                return ("COMPARISON: UNAVAILABLE - RUN CANCELLED",)
            return ("COMPARISON: PENDING",)
        if comparison.adaptive is None:
            raise TypeError("completed comparison snapshot omitted its adaptive lane")
        return (
            "COMPARISON: NEUTRAL FIXED AND ADAPTIVE LANES",
            (
                "COMPARISON CLASSIFICATIONS: "
                f"FIXED={comparison.baseline.classification.value} "
                f"ADAPTIVE={comparison.adaptive.classification.value}"
            ),
            *self._render_comparison_lane(comparison.baseline),
            *self._render_comparison_lane(comparison.adaptive),
        )

    def render_sections(self) -> RenderedSections:
        """Return every plain semantic section from the current projection."""

        return RenderedSections(
            connection=self.render_connection(),
            identity=self.render_identity(),
            outcome=self.render_outcome(),
            operations=self.render_operations(),
            transport=self.render_transport(),
            envelope=self.render_envelope(),
            advisory=self.render_advisory(),
            timeline=self.render_timeline(),
            evidence=self.render_evidence(),
            deterministic=self.render_deterministic(),
            actions=self.render_actions(),
            missing=self.render_missing(),
            comparison=self.render_comparison(),
        )


__all__ = [
    "ConnectionPhase",
    "OperationalStatusAvailability",
    "OperatorViewState",
    "RenderedSections",
    "ViewStateProtocolError",
    "ViewStateProtocolErrorCode",
]
