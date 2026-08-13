"""Offline ADK mutation-seam behavior."""

from __future__ import annotations

import asyncio

import pytest
from google.adk.tools import ToolContext

from reconcile.scenarios.adk_mutation import AdkMutationError, run_adk_mutation

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
