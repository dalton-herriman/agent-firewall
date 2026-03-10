from __future__ import annotations

from typing import Protocol

import httpx

from agent_firewall.models.config import AdapterConfig
from agent_firewall.models.tooling import ToolExecutionResult, ToolInvocationDecision, ToolInvocationRequest


class ToolExecutor(Protocol):
    async def execute(
        self,
        *,
        adapter: AdapterConfig,
        request: ToolInvocationRequest,
        decision: ToolInvocationDecision,
    ) -> ToolExecutionResult:
        ...


class HttpToolExecutor:
    async def execute(
        self,
        *,
        adapter: AdapterConfig,
        request: ToolInvocationRequest,
        decision: ToolInvocationDecision,
    ) -> ToolExecutionResult:
        async with httpx.AsyncClient(timeout=adapter.timeout_seconds) as client:
            response = await client.post(
                adapter.target_uri,
                json={
                    "agent_id": request.agent_id,
                    "tool_name": request.tool_name,
                    "tool_args": request.tool_args,
                    "metadata": request.metadata,
                },
            )
            response.raise_for_status()
            payload = response.json() if response.content else {}
        return ToolExecutionResult(
            tool_name=request.tool_name,
            status="executed",
            output=payload,
            decision=decision,
        )
