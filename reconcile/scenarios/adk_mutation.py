"""Credential-free ADK seam for one deterministic scenario mutation."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
from collections.abc import AsyncGenerator, Callable, Mapping
from functools import wraps
from typing import Any, cast

from google.adk.agents import LlmAgent
from google.adk.models import LlmRequest, LlmResponse
from google.adk.models.base_llm import BaseLlm
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools import FunctionTool
from google.adk.utils.context_utils import find_context_parameter
from google.genai import types
from pydantic import ConfigDict, JsonValue, PrivateAttr, TypeAdapter, ValidationError

from reconcile.contracts.base import (
    ArgumentsObject,
    Identifier,
    NonEmptySmallJsonObject,
    canonical_json_value_bytes,
    reject_sensitive_keys,
)

_APP_NAME = "reconcile_scenario_mutation"
_AGENT_NAME = "scenario_mutation_agent"
_MODEL_NAME = "reconcile-scripted-mutation"
_USER_ID = "scenario-runner"
_MAX_ARGUMENT_BYTES = 16_384
_MAX_PUBLIC_RESPONSE_BYTES = 4_096

_ARGUMENTS_ADAPTER = TypeAdapter(ArgumentsObject)
_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)
_PUBLIC_RESPONSE_ADAPTER = TypeAdapter(NonEmptySmallJsonObject)

type MutationTool = Callable[..., object]
type PublicObject = dict[str, JsonValue]


class AdkMutationError(RuntimeError):
    """A safe failure raised when the local ADK mutation turn is incomplete."""


def _isolated_json_object(value: Mapping[str, JsonValue]) -> PublicObject:
    return cast(PublicObject, json.loads(canonical_json_value_bytes(dict(value))))


def _validate_object(
    value: Mapping[str, JsonValue],
    *,
    adapter: TypeAdapter[Any],
    byte_limit: int,
    label: str,
) -> PublicObject:
    try:
        validated = adapter.validate_python(dict(value), strict=True)
        reject_sensitive_keys(validated)
        payload = canonical_json_value_bytes(validated)
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError(f"{label} is invalid") from error
    if len(payload) > byte_limit:
        raise ValueError(f"{label} exceeds its byte limit")
    return cast(PublicObject, json.loads(payload))


def _validate_identifier(value: str, *, label: str) -> str:
    try:
        return _IDENTIFIER_ADAPTER.validate_python(value, strict=True)
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError(f"{label} is invalid") from error


def _validate_tool_signature(tool: MutationTool, arguments: PublicObject) -> str:
    if inspect.iscoroutinefunction(tool) or inspect.isasyncgenfunction(tool):
        raise TypeError("the ADK mutation tool must be synchronous")
    name = getattr(tool, "__name__", None)
    if not isinstance(name, str):
        raise TypeError("the ADK mutation tool must have a stable function name")
    tool_name = _validate_identifier(name, label="tool name")
    try:
        signature = inspect.signature(tool)
    except (TypeError, ValueError) as error:
        raise TypeError(
            "the ADK mutation tool must have an inspectable signature"
        ) from error

    if any(
        parameter.kind
        in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
        for parameter in signature.parameters.values()
    ):
        raise TypeError("the ADK mutation tool must declare closed arguments")

    context_name = find_context_parameter(tool)
    if context_name is None and "tool_context" in signature.parameters:
        context_name = "tool_context"
    if context_name is not None and context_name in arguments:
        raise ValueError("tool context is controller-owned")

    bound_arguments: dict[str, object] = dict(arguments)
    if context_name is not None:
        bound_arguments[context_name] = object()
    try:
        signature.bind(**bound_arguments)
    except TypeError as error:
        raise ValueError("tool arguments do not match the supplied tool") from error
    return tool_name


class ScriptedModel(BaseLlm):
    """Two-turn local model: one fixed tool call, then one fixed completion."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    tool_name: Identifier
    function_call_id: Identifier
    arguments: ArgumentsObject
    public_response: NonEmptySmallJsonObject

    _turn_count: int = PrivateAttr(default=0)
    _public_response_seen: bool = PrivateAttr(default=False)

    @property
    def turn_count(self) -> int:
        return self._turn_count

    @property
    def public_response_seen(self) -> bool:
        return self._public_response_seen

    async def generate_content_async(
        self,
        llm_request: LlmRequest,
        stream: bool = False,
    ) -> AsyncGenerator[LlmResponse, None]:
        if stream:
            raise AdkMutationError("streaming is not supported by the scripted model")
        if set(llm_request.tools_dict) != {self.tool_name}:
            raise AdkMutationError("the scripted model requires exactly one tool")

        self._turn_count += 1
        if self._turn_count == 1:
            if _function_responses(llm_request):
                raise AdkMutationError(
                    "the first model turn cannot contain a tool result"
                )
            content = types.Content(
                role="model",
                parts=[
                    types.Part(
                        function_call=types.FunctionCall(
                            id=self.function_call_id,
                            name=self.tool_name,
                            args=_isolated_json_object(self.arguments),
                        )
                    )
                ],
            )
        elif self._turn_count == 2:
            responses = _function_responses(llm_request)
            if len(responses) != 1:
                raise AdkMutationError("ADK did not record exactly one tool result")
            response = responses[0]
            if response.id != self.function_call_id or response.name != self.tool_name:
                raise AdkMutationError(
                    "ADK changed the scripted function-call identity"
                )
            if not isinstance(response.response, dict) or (
                canonical_json_value_bytes(response.response)
                != canonical_json_value_bytes(self.public_response)
            ):
                raise AdkMutationError("ADK exposed an unexpected tool response")
            self._public_response_seen = True
            content = types.Content(
                role="model",
                parts=[types.Part(text="The declared tool response was recorded.")],
            )
        else:
            raise AdkMutationError("the scripted model was invoked more than twice")

        yield LlmResponse(content=content, partial=False)


def _function_responses(llm_request: LlmRequest) -> tuple[types.FunctionResponse, ...]:
    return tuple(
        part.function_response
        for content in llm_request.contents
        for part in content.parts or ()
        if part.function_response is not None
    )


def _public_tool_wrapper(
    tool: MutationTool,
    public_response: PublicObject,
    invocation_markers: list[None],
) -> MutationTool:
    @wraps(tool)
    def invoke(*args: object, **kwargs: object) -> PublicObject:
        invocation_markers.append(None)
        if len(invocation_markers) != 1:
            raise AdkMutationError("ADK attempted more than one mutation")
        tool(*args, **kwargs)
        return _isolated_json_object(public_response)

    return invoke


async def _run_adk_mutation(
    *,
    tool: MutationTool,
    tool_name: str,
    arguments: PublicObject,
    public_response: PublicObject,
    function_call_id: str,
    invocation_id: str,
) -> PublicObject:
    invocation_markers: list[None] = []
    wrapped_tool = _public_tool_wrapper(tool, public_response, invocation_markers)
    function_tool = FunctionTool(wrapped_tool)
    if function_tool.name != tool_name:
        raise AdkMutationError("ADK changed the supplied tool name")

    model = ScriptedModel(
        model=_MODEL_NAME,
        tool_name=tool_name,
        function_call_id=function_call_id,
        arguments=arguments,
        public_response=public_response,
    )
    agent = LlmAgent(
        name=_AGENT_NAME,
        description="Runs one locally scripted scenario mutation.",
        instruction="Issue the single declared tool call and then stop.",
        model=model,
        tools=[function_tool],
    )
    session_service = InMemorySessionService()
    session_id = (
        "session-" + hashlib.sha256(invocation_id.encode("utf-8")).hexdigest()[:32]
    )
    await session_service.create_session(
        app_name=_APP_NAME,
        user_id=_USER_ID,
        session_id=session_id,
    )
    runner = Runner(
        app_name=_APP_NAME,
        agent=agent,
        session_service=session_service,
    )

    events = []
    try:
        async for event in runner.run_async(
            user_id=_USER_ID,
            session_id=session_id,
            invocation_id=invocation_id,
            new_message=types.Content(
                role="user",
                parts=[types.Part(text="Run the declared scenario mutation once.")],
            ),
        ):
            events.append(event)
    except Exception as error:
        raise AdkMutationError("the local ADK mutation did not complete") from error
    finally:
        await runner.close()

    calls = tuple(call for event in events for call in event.get_function_calls())
    responses = tuple(
        response for event in events for response in event.get_function_responses()
    )
    if len(invocation_markers) != 1 or len(calls) != 1 or len(responses) != 1:
        raise AdkMutationError("ADK did not execute exactly one mutation turn")
    call = calls[0]
    response = responses[0]
    if (
        call.id != function_call_id
        or call.name != tool_name
        or canonical_json_value_bytes(call.args or {})
        != canonical_json_value_bytes(arguments)
        or response.id != function_call_id
        or response.name != tool_name
        or not model.public_response_seen
        or model.turn_count != 2
    ):
        raise AdkMutationError("ADK did not preserve the mutation identity")
    if not isinstance(response.response, dict):
        raise AdkMutationError("ADK returned a malformed public tool response")
    return _validate_object(
        response.response,
        adapter=_PUBLIC_RESPONSE_ADAPTER,
        byte_limit=_MAX_PUBLIC_RESPONSE_BYTES,
        label="public response",
    )


def run_adk_mutation(
    tool: MutationTool,
    *,
    arguments: Mapping[str, JsonValue],
    public_response: Mapping[str, JsonValue],
    function_call_id: str,
    invocation_id: str,
) -> PublicObject:
    """Invoke one synchronous side-effecting tool through an offline ADK runner."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError("run_adk_mutation cannot run inside an active event loop")

    validated_arguments = _validate_object(
        arguments,
        adapter=_ARGUMENTS_ADAPTER,
        byte_limit=_MAX_ARGUMENT_BYTES,
        label="tool arguments",
    )
    validated_response = _validate_object(
        public_response,
        adapter=_PUBLIC_RESPONSE_ADAPTER,
        byte_limit=_MAX_PUBLIC_RESPONSE_BYTES,
        label="public response",
    )
    validated_call_id = _validate_identifier(
        function_call_id,
        label="function-call identifier",
    )
    if validated_call_id.startswith("adk-"):
        raise ValueError("function-call identifier uses an ADK-reserved prefix")
    validated_invocation_id = _validate_identifier(
        invocation_id,
        label="invocation identifier",
    )
    tool_name = _validate_tool_signature(tool, validated_arguments)

    return asyncio.run(
        _run_adk_mutation(
            tool=tool,
            tool_name=tool_name,
            arguments=validated_arguments,
            public_response=validated_response,
            function_call_id=validated_call_id,
            invocation_id=validated_invocation_id,
        )
    )


__all__ = ["AdkMutationError", "ScriptedModel", "run_adk_mutation"]
