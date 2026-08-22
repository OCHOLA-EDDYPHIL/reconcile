"""Offline ADK mutation-seam behavior."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from google.adk.tools import ToolContext

from reconcile.contracts import (
    ActionPermitState,
    PermitCompletionOutcome,
    TargetBinding,
)
from reconcile.controller.permits import PermitAuthority
from reconcile.persistence.permits import ActionPermitStore, PermitAuditKind
from reconcile.persistence.sqlite_runtime import SqliteDurableRuntimeStore
from reconcile.scenarios.adk_mutation import (
    AdkMutationError,
    ExplicitMutationRejection,
    run_adk_mutation,
    run_permitted_adk_mutation,
)
from tests._permit_support import make_permit_certificate
from tests.contract._factories import NOW

pytestmark = pytest.mark.unit


def test_actual_adk_invokes_exactly_one_tool_with_stable_identity() -> None:
    calls: list[tuple[str, int, str]] = []

    def create_object(
        object_name: str,
        byte_count: int,
        tool_context: ToolContext,
    ) -> dict[str, object]:
        calls.append(
            (
                object_name,
                byte_count,
                tool_context.function_call_id,
            )
        )
        return {
            "private_generation": "1700000000000000",
            "private_receipt": {"object": object_name},
        }

    result = run_adk_mutation(
        create_object,
        arguments={"object_name": "receipts/order-7.json", "byte_count": 37},
        public_response={"accepted": True, "operation_id": "operation-7"},
        function_call_id="function-call-7",
        invocation_id="invocation-7",
    )

    assert result == {"accepted": True, "operation_id": "operation-7"}
    assert calls == [
        (
            "receipts/order-7.json",
            37,
            "function-call-7",
        )
    ]
    assert "private_generation" not in result
    assert "private_receipt" not in result


def test_private_non_json_tool_result_never_crosses_the_public_boundary() -> None:
    private_result = object()
    calls = 0

    def mutate(operation_id: str) -> object:
        nonlocal calls
        calls += 1
        return private_result

    result = run_adk_mutation(
        mutate,
        arguments={"operation_id": "operation-7"},
        public_response={"status": "response-recorded"},
        function_call_id="function-call-7",
        invocation_id="invocation-7",
    )

    assert calls == 1
    assert result == {"status": "response-recorded"}
    assert private_result not in result.values()


@pytest.mark.parametrize(
    ("arguments", "public_response", "message"),
    (
        (
            {"operation_id": "operation-7", "unexpected": True},
            {"accepted": True},
            "tool arguments do not match",
        ),
        (
            {"operation_id": "operation-7"},
            {"access_token": "visible-secret"},
            "public response is invalid",
        ),
        (
            {"operation_id": "operation-7"},
            {"detail": "x" * 4_097},
            "public response exceeds",
        ),
    ),
)
def test_invalid_inputs_fail_before_the_tool_is_invoked(
    arguments: dict[str, object],
    public_response: dict[str, object],
    message: str,
) -> None:
    calls = 0

    def mutate(operation_id: str) -> dict[str, bool]:
        nonlocal calls
        calls += 1
        return {"created": True}

    with pytest.raises(ValueError, match=message):
        run_adk_mutation(
            mutate,
            arguments=arguments,  # type: ignore[arg-type]
            public_response=public_response,  # type: ignore[arg-type]
            function_call_id="function-call-7",
            invocation_id="invocation-7",
        )

    assert calls == 0


def test_tool_failure_returns_only_a_safe_seam_error() -> None:
    def mutate(operation_id: str) -> dict[str, bool]:
        raise RuntimeError(f"private provider detail for {operation_id}")

    with pytest.raises(AdkMutationError) as raised:
        run_adk_mutation(
            mutate,
            arguments={"operation_id": "operation-7"},
            public_response={"accepted": True},
            function_call_id="function-call-7",
            invocation_id="invocation-7",
        )

    assert str(raised.value) == "the local ADK mutation did not complete"
    assert "private provider detail" not in str(raised.value)


def test_reserved_call_id_and_async_tool_are_rejected_before_invocation() -> None:
    calls = 0

    async def mutate(operation_id: str) -> dict[str, bool]:
        nonlocal calls
        calls += 1
        return {"created": True}

    with pytest.raises(TypeError, match="must be synchronous"):
        run_adk_mutation(
            mutate,
            arguments={"operation_id": "operation-7"},
            public_response={"accepted": True},
            function_call_id="function-call-7",
            invocation_id="invocation-7",
        )
    with pytest.raises(ValueError, match="reserved prefix"):
        run_adk_mutation(
            lambda operation_id: {"created": True},
            arguments={"operation_id": "operation-7"},
            public_response={"accepted": True},
            function_call_id="adk-function-call-7",
            invocation_id="invocation-7",
        )

    assert calls == 0


def test_sync_seam_rejects_nested_event_loop_use() -> None:
    async def invoke() -> None:
        with pytest.raises(RuntimeError, match="active event loop"):
            run_adk_mutation(
                lambda operation_id: {"created": True},
                arguments={"operation_id": "operation-7"},
                public_response={"accepted": True},
                function_call_id="function-call-7",
                invocation_id="invocation-7",
            )

    asyncio.run(invoke())


class _SequenceClock:
    def __init__(self, *offsets: int) -> None:
        self._values = iter(NOW + timedelta(seconds=value) for value in offsets)

    def __call__(self):
        return next(self._values)


def _named_promotion_tool(callback):
    callback.__name__ = "promote-cloud-run-traffic"
    return callback


def test_permit_is_claimed_in_before_tool_callback_and_completed_afterward(
    tmp_path,
) -> None:
    certificate, arguments, precondition = make_permit_certificate()
    store = SqliteDurableRuntimeStore(tmp_path / "runtime.sqlite3")
    permit = asyncio.run(
        PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=6),
        ).issue_permit(certificate)
    )
    assert permit is not None
    calls: list[tuple[str, int]] = []

    @_named_promotion_tool
    def promote(release_id: str, percent: int) -> None:
        calls.append((release_id, percent))

    authority = PermitAuthority(
        store,
        clock=_SequenceClock(7, 8),
        claim_id_factory=lambda: "claim-adk-success",
    )
    response = run_permitted_adk_mutation(
        promote,
        arguments=arguments,
        public_response={"accepted": True},
        function_call_id="function-call-permitted",
        invocation_id="invocation-permitted",
        authority=authority,
        permit_id=permit.permit_id,
        certificate=certificate,
        tool_version=permit.tool_version,
        target=certificate.target,
        precondition=precondition,
    )

    assert response == {"accepted": True}
    assert calls == [("r-7", 100)]
    stored = asyncio.run(store.get_permit(permit.permit_id))
    assert stored.state is ActionPermitState.COMPLETED
    assert stored.completion_outcome is PermitCompletionOutcome.SUCCEEDED
    assert [
        event.kind for event in asyncio.run(store.permit_audit_events(permit.permit_id))
    ] == [
        PermitAuditKind.ISSUED,
        PermitAuditKind.CLAIMED,
        PermitAuditKind.COMPLETED,
    ]


def test_wrong_target_replay_missing_and_model_forgery_make_no_outbound_call(
    tmp_path,
) -> None:
    certificate, arguments, precondition = make_permit_certificate()
    store = SqliteDurableRuntimeStore(tmp_path / "runtime.sqlite3")
    permit = asyncio.run(
        PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=6),
        ).issue_permit(certificate)
    )
    assert permit is not None
    calls = 0

    @_named_promotion_tool
    def promote(release_id: str, percent: int) -> None:
        nonlocal calls
        calls += 1

    wrong_target = TargetBinding.model_validate(
        certificate.target.model_copy(
            update={"resource": {"object_name": "wrong-target"}}
        )
    )
    wrong_authority = PermitAuthority(
        store,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "claim-wrong-target",
    )
    with pytest.raises(AdkMutationError):
        run_permitted_adk_mutation(
            promote,
            arguments=arguments,
            public_response={"accepted": True},
            function_call_id="function-call-wrong",
            invocation_id="invocation-wrong",
            authority=wrong_authority,
            permit_id=permit.permit_id,
            certificate=certificate,
            tool_version=permit.tool_version,
            target=wrong_target,
            precondition=precondition,
        )
    assert calls == 0
    assert asyncio.run(store.get_permit(permit.permit_id)).state is (
        ActionPermitState.ISSUED
    )

    missing_authority = PermitAuthority(
        store,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "claim-missing",
    )
    with pytest.raises(AdkMutationError):
        run_permitted_adk_mutation(
            promote,
            arguments=arguments,
            public_response={"accepted": True},
            function_call_id="function-call-missing",
            invocation_id="invocation-missing",
            authority=missing_authority,
            permit_id="permit-missing",
            certificate=certificate,
            tool_version=permit.tool_version,
            target=certificate.target,
            precondition=precondition,
        )
    assert calls == 0

    with pytest.raises(ValueError, match="controller-owned"):
        run_permitted_adk_mutation(
            lambda release_id, percent, permit_id: None,
            arguments={**arguments, "permit_id": "model-forged"},
            public_response={"accepted": True},
            function_call_id="function-call-forged",
            invocation_id="invocation-forged",
            authority=missing_authority,
            permit_id=permit.permit_id,
            certificate=certificate,
            tool_version=permit.tool_version,
            target=certificate.target,
            precondition=precondition,
        )
    assert calls == 0

    success_authority = PermitAuthority(
        store,
        clock=_SequenceClock(8, 9),
        claim_id_factory=lambda: "claim-success",
    )
    run_permitted_adk_mutation(
        promote,
        arguments=arguments,
        public_response={"accepted": True},
        function_call_id="function-call-success",
        invocation_id="invocation-success",
        authority=success_authority,
        permit_id=permit.permit_id,
        certificate=certificate,
        tool_version=permit.tool_version,
        target=certificate.target,
        precondition=precondition,
    )
    assert calls == 1

    replay_authority = PermitAuthority(
        store,
        clock=lambda: NOW + timedelta(seconds=10),
        claim_id_factory=lambda: "claim-replay",
    )
    with pytest.raises(AdkMutationError):
        run_permitted_adk_mutation(
            promote,
            arguments=arguments,
            public_response={"accepted": True},
            function_call_id="function-call-replay",
            invocation_id="invocation-replay",
            authority=replay_authority,
            permit_id=permit.permit_id,
            certificate=certificate,
            tool_version=permit.tool_version,
            target=certificate.target,
            precondition=precondition,
        )
    assert calls == 1


@pytest.mark.parametrize(
    ("exception", "expected_outcome", "expected_audit"),
    (
        (
            TimeoutError("provider response timed out"),
            PermitCompletionOutcome.OUTCOME_UNKNOWN,
            PermitAuditKind.OUTCOME_UNKNOWN,
        ),
        (
            ExplicitMutationRejection("provider rejected the precondition"),
            PermitCompletionOutcome.REJECTED,
            PermitAuditKind.REJECTED,
        ),
    ),
)
def test_provider_failure_after_claim_is_terminal_and_never_replayed(
    tmp_path,
    exception: Exception,
    expected_outcome: PermitCompletionOutcome,
    expected_audit: PermitAuditKind,
) -> None:
    certificate, arguments, precondition = make_permit_certificate()
    store = SqliteDurableRuntimeStore(tmp_path / f"{expected_outcome.value}.sqlite3")
    permit = asyncio.run(
        PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=6),
        ).issue_permit(certificate)
    )
    assert permit is not None
    calls = 0

    @_named_promotion_tool
    def promote(release_id: str, percent: int) -> None:
        nonlocal calls
        calls += 1
        raise exception

    authority = PermitAuthority(
        store,
        clock=_SequenceClock(7, 8),
        claim_id_factory=lambda: "claim-provider-failure",
    )
    with pytest.raises(AdkMutationError):
        run_permitted_adk_mutation(
            promote,
            arguments=arguments,
            public_response={"accepted": True},
            function_call_id="function-call-failure",
            invocation_id="invocation-failure",
            authority=authority,
            permit_id=permit.permit_id,
            certificate=certificate,
            tool_version=permit.tool_version,
            target=certificate.target,
            precondition=precondition,
        )
    assert calls == 1
    stored = asyncio.run(store.get_permit(permit.permit_id))
    assert stored.state is ActionPermitState.COMPLETED
    assert stored.completion_outcome is expected_outcome
    assert asyncio.run(store.permit_audit_events(permit.permit_id))[-1].kind is (
        expected_audit
    )


class _CrashAfterClaimStore:
    def __init__(self, delegate: ActionPermitStore) -> None:
        self._delegate = delegate

    async def issue_permit(self, permit):
        return await self._delegate.issue_permit(permit)

    async def get_permit(self, permit_id):
        return await self._delegate.get_permit(permit_id)

    async def claim_permit(self, request):
        await self._delegate.claim_permit(request)
        raise RuntimeError("simulated process loss after durable claim")

    async def complete_permit(self, request):
        return await self._delegate.complete_permit(request)

    async def permit_audit_events(self, permit_id):
        return await self._delegate.permit_audit_events(permit_id)


def test_crash_after_claim_leaves_no_automatic_redispatch_path(tmp_path) -> None:
    certificate, arguments, precondition = make_permit_certificate()
    store = SqliteDurableRuntimeStore(tmp_path / "runtime.sqlite3")
    permit = asyncio.run(
        PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=6),
        ).issue_permit(certificate)
    )
    assert permit is not None
    calls = 0

    @_named_promotion_tool
    def promote(release_id: str, percent: int) -> None:
        nonlocal calls
        calls += 1

    crashing_authority = PermitAuthority(
        _CrashAfterClaimStore(store),
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "claim-crashed",
    )
    with pytest.raises(AdkMutationError):
        run_permitted_adk_mutation(
            promote,
            arguments=arguments,
            public_response={"accepted": True},
            function_call_id="function-call-crash",
            invocation_id="invocation-crash",
            authority=crashing_authority,
            permit_id=permit.permit_id,
            certificate=certificate,
            tool_version=permit.tool_version,
            target=certificate.target,
            precondition=precondition,
        )
    assert calls == 0
    assert asyncio.run(store.get_permit(permit.permit_id)).state is (
        ActionPermitState.CLAIMED
    )

    restarted_authority = PermitAuthority(
        store,
        clock=lambda: NOW + timedelta(seconds=8),
        claim_id_factory=lambda: "claim-restarted",
    )
    with pytest.raises(AdkMutationError):
        run_permitted_adk_mutation(
            promote,
            arguments=arguments,
            public_response={"accepted": True},
            function_call_id="function-call-restarted",
            invocation_id="invocation-restarted",
            authority=restarted_authority,
            permit_id=permit.permit_id,
            certificate=certificate,
            tool_version=permit.tool_version,
            target=certificate.target,
            precondition=precondition,
        )
    assert calls == 0
