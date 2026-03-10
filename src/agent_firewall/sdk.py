from __future__ import annotations

from collections.abc import Awaitable, Callable
from inspect import isawaitable
from typing import Any, TypeVar

from agent_firewall.models.tooling import ToolInvocationDecision, ToolInvocationRequest
from agent_firewall.service import FirewallService

T = TypeVar("T")


class AgentFirewallSDK:
    def __init__(self, engine: FirewallService) -> None:
        self._engine = engine

    async def evaluate(self, request: ToolInvocationRequest) -> ToolInvocationDecision:
        return await self._engine.evaluate(request)

    async def authorize(
        self,
        *,
        tenant_id: str = "default",
        project_id: str | None = None,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ToolInvocationDecision:
        request = ToolInvocationRequest(
            tenant_id=tenant_id,
            project_id=project_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=tool_args or {},
            metadata=metadata or {},
        )
        return await self.evaluate(request)

    async def call_tool(
        self,
        *,
        tenant_id: str = "default",
        project_id: str | None = None,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        callback: Callable[[], T | Awaitable[T]],
        metadata: dict[str, Any] | None = None,
    ) -> T:
        decision = await self.authorize(
            tenant_id=tenant_id,
            project_id=project_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
            metadata=metadata,
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)
        result = callback()
        if isawaitable(result):
            return await result
        return result
