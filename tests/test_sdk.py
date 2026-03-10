import pytest

from agent_firewall.cache import InMemoryRateLimiter
from agent_firewall.middleware import GuardedTool, tool_guard
from agent_firewall.models.config import AdapterConfig
from agent_firewall.models.policy import PolicyCondition, PolicyRule
from agent_firewall.repositories.memory import (
    InMemoryAdapterRepository,
    InMemoryAuditLogRepository,
    InMemoryPolicyRepository,
)
from agent_firewall.sdk import AgentFirewallSDK
from agent_firewall.service import FirewallService
from agent_firewall.config import Settings


def build_sdk() -> AgentFirewallSDK:
    engine = FirewallService(
        settings=Settings(app_env="test", default_policy_mode="deny"),
        policy_repository=InMemoryPolicyRepository(
            [
                PolicyRule(
                    name="allow city",
                    action="allow",
                    tool="weather.lookup",
                    priority=1,
                    conditions=[PolicyCondition(field="tool_args.city", operator="eq", value="Chicago")],
                )
            ]
        ),
        audit_log_repository=InMemoryAuditLogRepository(),
        adapter_repository=InMemoryAdapterRepository(
            [AdapterConfig(tool_name="weather.lookup", target_uri="https://example.com/weather")]
        ),
        rate_limiter=InMemoryRateLimiter(),
    )
    return AgentFirewallSDK(engine)


@pytest.mark.asyncio
async def test_guarded_tool_allows_authorized_call() -> None:
    sdk = build_sdk()
    tool = GuardedTool(
        sdk=sdk,
        agent_id="agent-1",
        tool_name="weather.lookup",
        callback=lambda city: f"weather for {city}",
    )

    result = await tool(city="Chicago")

    assert result == "weather for Chicago"


@pytest.mark.asyncio
async def test_guarded_tool_blocks_unauthorized_call() -> None:
    sdk = build_sdk()
    tool = GuardedTool(
        sdk=sdk,
        agent_id="agent-1",
        tool_name="weather.lookup",
        callback=lambda city: f"weather for {city}",
    )

    with pytest.raises(PermissionError):
        await tool(city="Austin")


@pytest.mark.asyncio
async def test_tool_guard_decorator_wraps_async_tool() -> None:
    sdk = build_sdk()

    @tool_guard(
        sdk=sdk,
        agent_id_getter=lambda agent_id, city: agent_id,
        tool_name="weather.lookup",
        tool_args_getter=lambda agent_id, city: {"city": city},
    )
    async def run_tool(agent_id: str, city: str) -> str:
        return f"weather for {city}"

    result = await run_tool("agent-1", "Chicago")

    assert result == "weather for Chicago"
