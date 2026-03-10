from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from agent_firewall.sdk import AgentFirewallSDK

T = TypeVar("T")


def guard_langchain_tool(
    *,
    sdk: AgentFirewallSDK,
    agent_id: str,
    tool_name: str,
    metadata: dict[str, Any] | None = None,
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        async def wrapper(**tool_args: Any) -> T:
            return await sdk.call_tool(
                agent_id=agent_id,
                tool_name=tool_name,
                tool_args=tool_args,
                metadata=metadata,
                callback=lambda: func(**tool_args),
            )

        return wrapper

    return decorator
