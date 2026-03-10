from __future__ import annotations

import asyncio
from typing import Protocol

import httpx

from agent_firewall.config import Settings
from agent_firewall.models.config import AdapterConfig
from agent_firewall.models.tooling import ToolExecutionResult, ToolInvocationDecision, ToolInvocationRequest
from agent_firewall.reliability import ReliabilityState


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
    def __init__(self, settings: Settings, reliability_state: ReliabilityState | None = None) -> None:
        self._settings = settings
        self._reliability_state = reliability_state or ReliabilityState()

    async def execute(
        self,
        *,
        adapter: AdapterConfig,
        request: ToolInvocationRequest,
        decision: ToolInvocationDecision,
    ) -> ToolExecutionResult:
        circuit_key = f"{request.tenant_id}:{request.tool_name}"
        if self._reliability_state.is_circuit_open(circuit_key):
            raise RuntimeError("circuit breaker open")

        idempotency_key = self._idempotency_key(request)
        cached = self._reliability_state.get_cached_result(idempotency_key) if idempotency_key else None
        if cached is not None:
            return cached  # type: ignore[return-value]

        attempts = 0
        backoff = self._settings.execution.initial_backoff_seconds
        last_exc: Exception | None = None
        while attempts <= self._settings.execution.max_retries:
            attempts += 1
            try:
                async with httpx.AsyncClient(timeout=adapter.timeout_seconds) as client:
                    response = await client.post(
                        adapter.target_uri,
                        json={
                            "agent_id": request.agent_id,
                            "tool_name": request.tool_name,
                            "tool_args": request.tool_args,
                            "metadata": request.metadata,
                        },
                        headers={"Idempotency-Key": idempotency_key} if idempotency_key else None,
                    )
                    response.raise_for_status()
                    payload = response.json() if response.content else {}
                result = ToolExecutionResult(
                    tenant_id=request.tenant_id,
                    project_id=request.project_id,
                    tool_name=request.tool_name,
                    status="executed",
                    attempts=attempts,
                    idempotency_key=idempotency_key,
                    output=payload,
                    decision=decision,
                )
                self._reliability_state.record_success(circuit_key)
                if idempotency_key:
                    self._reliability_state.cache_result(idempotency_key, result)
                return result
            except (httpx.HTTPError, httpx.TimeoutException) as exc:
                last_exc = exc
                self._reliability_state.record_failure(
                    circuit_key,
                    threshold=self._settings.execution.circuit_breaker_threshold,
                    reset_seconds=self._settings.execution.circuit_breaker_reset_seconds,
                )
                if attempts > self._settings.execution.max_retries:
                    break
                await asyncio.sleep(backoff)
                backoff *= 2
        raise RuntimeError(f"tool execution failed after {attempts} attempts") from last_exc

    def _idempotency_key(self, request: ToolInvocationRequest) -> str | None:
        raw = request.metadata.get("idempotency_key")
        return str(raw) if raw else None
