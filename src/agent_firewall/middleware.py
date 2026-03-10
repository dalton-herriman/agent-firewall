from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, TypeVar

from agent_firewall.sdk import AgentFirewallSDK

T = TypeVar("T")


class ToolHook(Protocol):
    async def __call__(
        self,
        *,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        ...


async def sdk_hook(
    sdk: AgentFirewallSDK,
    *,
    tenant_id: str = "default",
    project_id: str | None = None,
    agent_id: str,
    tool_name: str,
    tool_args: dict[str, Any],
    metadata: dict[str, Any] | None = None,
) -> None:
    decision = await sdk.authorize(
        tenant_id=tenant_id,
        project_id=project_id,
        agent_id=agent_id,
        tool_name=tool_name,
        tool_args=tool_args,
        metadata=metadata,
    )
    if not decision.allowed:
        raise PermissionError(decision.reason)


def tool_guard(
    *,
    sdk: AgentFirewallSDK,
    tenant_id_getter: Callable[..., str] | None = None,
    project_id_getter: Callable[..., str | None] | None = None,
    agent_id_getter: Callable[..., str],
    tool_name: str,
    tool_args_getter: Callable[..., dict[str, Any]],
    metadata_getter: Callable[..., dict[str, Any] | None] | None = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        if inspect.iscoroutinefunction(func):
            async def async_wrapper(*args: Any, **kwargs: Any) -> T:
                await sdk_hook(
                    sdk,
                    tenant_id=tenant_id_getter(*args, **kwargs) if tenant_id_getter else "default",
                    project_id=project_id_getter(*args, **kwargs) if project_id_getter else None,
                    agent_id=agent_id_getter(*args, **kwargs),
                    tool_name=tool_name,
                    tool_args=tool_args_getter(*args, **kwargs),
                    metadata=metadata_getter(*args, **kwargs) if metadata_getter else None,
                )
                return await func(*args, **kwargs)

            return async_wrapper

        def sync_wrapper(*args: Any, **kwargs: Any) -> T:
            raise RuntimeError("tool_guard requires async tools; use GuardedTool for sync call sites")

        return sync_wrapper

    return decorator


class GuardedTool:
    def __init__(
        self,
        *,
        sdk: AgentFirewallSDK,
        tenant_id: str = "default",
        project_id: str | None = None,
        agent_id: str,
        tool_name: str,
        callback: Callable[..., T],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._sdk = sdk
        self._tenant_id = tenant_id
        self._project_id = project_id
        self._agent_id = agent_id
        self._tool_name = tool_name
        self._callback = callback
        self._metadata = metadata or {}

    async def __call__(self, **tool_args: Any) -> T:
        return await self._sdk.call_tool(
            tenant_id=self._tenant_id,
            project_id=self._project_id,
            agent_id=self._agent_id,
            tool_name=self._tool_name,
            tool_args=tool_args,
            metadata=self._metadata,
            callback=lambda: self._callback(**tool_args),
        )
