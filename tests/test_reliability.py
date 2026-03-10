import pytest

from agent_firewall.config import ExecutionConfig, Settings
from agent_firewall.executor import HttpToolExecutor
from agent_firewall.models.config import AdapterConfig
from agent_firewall.models.tooling import ToolInvocationDecision, ToolInvocationRequest
from agent_firewall.reliability import ReliabilityState


class FlakyExecutor(HttpToolExecutor):
    def __init__(self, failures_before_success: int) -> None:
        super().__init__(
            Settings(app_env="test", execution=ExecutionConfig(max_retries=3, initial_backoff_seconds=0.0)),
            reliability_state=ReliabilityState(),
        )
        self.failures_before_success = failures_before_success
        self.calls = 0

    async def execute(self, *, adapter, request, decision):
        return await super().execute(adapter=adapter, request=request, decision=decision)


@pytest.mark.asyncio
async def test_idempotent_result_is_reused(monkeypatch) -> None:
    executor = HttpToolExecutor(
        Settings(app_env="test", execution=ExecutionConfig(max_retries=0)),
        reliability_state=ReliabilityState(),
    )

    class Response:
        status_code = 200
        content = b'{"ok":true}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"ok": True}

    class Client:
        def __init__(self, *args, **kwargs):
            self.calls = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr("agent_firewall.executor.httpx.AsyncClient", Client)

    adapter = AdapterConfig(tool_name="weather.lookup", target_uri="https://example.com/weather")
    request = ToolInvocationRequest(
        tenant_id="default",
        agent_id="agent-1",
        tool_name="weather.lookup",
        tool_args={"city": "Chicago"},
        metadata={"idempotency_key": "abc"},
    )
    decision = ToolInvocationDecision(allowed=True, reason="matched")

    first = await executor.execute(adapter=adapter, request=request, decision=decision)
    second = await executor.execute(adapter=adapter, request=request, decision=decision)

    assert first.idempotency_key == "abc"
    assert second.output == first.output


def test_circuit_breaker_state_opens_after_threshold() -> None:
    state = ReliabilityState()
    key = "default:weather.lookup"
    state.record_failure(key, threshold=2, reset_seconds=30, now=100.0)
    assert state.is_circuit_open(key, now=100.0) is False
    state.record_failure(key, threshold=2, reset_seconds=30, now=101.0)
    assert state.is_circuit_open(key, now=101.0) is True
