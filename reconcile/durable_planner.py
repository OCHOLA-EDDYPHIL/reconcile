"""Trusted advisory planner precharge boundary."""

from __future__ import annotations

import hashlib

from reconcile.adaptive import (
    AdvisoryPlanner,
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
)
from reconcile.contracts.codec import canonical_json_bytes, decode_contract
from reconcile.contracts.planning import AdaptivePlannerInput
from reconcile.durable_application import (
    DurableExecutionContext,
    DurableProviderWindowUnavailable,
)


class DurableAdvisoryPlanner:
    """Route each real planner dispatch through one deterministic durable call."""

    def __init__(
        self,
        planner: AdvisoryPlanner,
        runtime: DurableExecutionContext,
        *,
        estimated_cost_microunits: int,
        minimum_remaining_ms: int = 0,
    ) -> None:
        try:
            metadata = planner.metadata
            plan = planner.plan
        except Exception:
            raise TypeError(
                "durable planner does not satisfy the strict protocol"
            ) from None
        if type(metadata) is not AdvisoryPlannerMetadata or not callable(plan):
            raise TypeError("durable planner does not satisfy the strict protocol")
        if type(estimated_cost_microunits) is not int or estimated_cost_microunits < 0:
            raise ValueError("planner estimated cost must be a nonnegative integer")
        if type(minimum_remaining_ms) is not int or minimum_remaining_ms < 0:
            raise ValueError("planner minimum remaining time must be nonnegative")
        self._planner = planner
        self._runtime = runtime
        self._metadata = metadata
        self._estimated_cost_microunits = estimated_cost_microunits
        self._minimum_remaining_ms = minimum_remaining_ms
        self._predispatch_refused = False
        self._sequence = 0

    @property
    def metadata(self) -> AdvisoryPlannerMetadata:
        return self._metadata

    @property
    def predispatch_refused(self) -> bool:
        return self._predispatch_refused

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        sealed = decode_contract(
            canonical_json_bytes(planner_input),
            AdaptivePlannerInput,
        )
        self._sequence += 1
        input_sha256 = hashlib.sha256(canonical_json_bytes(sealed)).hexdigest()
        call_id = (
            f"planner-{self._sequence:03d}-{sealed.phase.value.lower()}-"
            f"{input_sha256[:16]}"
        )
        try:
            turn = await self._runtime.call_provider(
                call_id,
                estimated_cost_microunits=self._estimated_cost_microunits,
                operation=lambda: self._planner.plan(sealed),
                minimum_remaining_ms=self._minimum_remaining_ms,
            )
        except DurableProviderWindowUnavailable:
            self._predispatch_refused = True
            raise
        if type(turn) is not AdvisoryPlannerTurn or turn.input_sha256 != input_sha256:
            raise ValueError("durable planner returned an unbound turn")
        return turn


__all__ = ["DurableAdvisoryPlanner"]
