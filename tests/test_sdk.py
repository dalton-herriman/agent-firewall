import pytest

from agent_firewall.cache import InMemoryRateLimiter
from agent_firewall.integrations.langchain import guard_langchain_tool
from agent_firewall.integrations.openai_agents import guard_openai_tool
from agent_firewall.middleware import GuardedTool, tool_guard
from agent_firewall.models.config import AdapterConfig, ToolArgumentSpec
from agent_firewall.models.policy import PolicyCondition, PolicyRule, PolicyResource, PolicySubject
from agent_firewall.policy import validate_policy_candidate
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
                    subject=PolicySubject(agent_ids=["agent-1"]),
                    resource=PolicyResource(tool_names=["weather.lookup"]),
                    priority=1,
                    conditions=[PolicyCondition(field="tool_args.city", operator="eq", value="Chicago")],
                )
            ]
        ),
        audit_log_repository=InMemoryAuditLogRepository(),
        adapter_repository=InMemoryAdapterRepository(
            [
                AdapterConfig(
                    tool_name="weather.lookup",
                    target_uri="https://example.com/weather",
                    schema=[ToolArgumentSpec(name="city", value_type="string", required=True)],
                )
            ]
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


@pytest.mark.asyncio
async def test_langchain_integration_wrapper() -> None:
    sdk = build_sdk()

    @guard_langchain_tool(sdk=sdk, agent_id="agent-1", tool_name="weather.lookup")
    async def run(city: str) -> str:
        return city.upper()

    assert await run(city="Chicago") == "CHICAGO"


@pytest.mark.asyncio
async def test_openai_integration_wrapper_blocks_denied_call() -> None:
    sdk = build_sdk()

    @guard_openai_tool(sdk=sdk, agent_id="agent-1", tool_name="weather.lookup")
    async def run(city: str) -> str:
        return city.upper()

    with pytest.raises(PermissionError):
        await run(city="Austin")


def test_policy_conflict_validation_detects_ambiguous_overlap() -> None:
    existing = [
        PolicyRule(
            name="allow fs",
            action="allow",
            subject=PolicySubject(agent_ids=["agent-1"]),
            resource=PolicyResource(tool_names=["filesystem.*"]),
            priority=10,
            conditions=[],
        )
    ]

    candidate = PolicyRule(
        name="deny fs",
        action="deny",
        subject=PolicySubject(agent_ids=["agent-1"]),
        resource=PolicyResource(tool_names=["filesystem.delete"]),
        priority=10,
        conditions=[],
    )

    result = validate_policy_candidate(candidate, existing)

    assert result.valid is False
    assert result.errors


def test_policy_model_supports_versioning() -> None:
    policy = PolicyRule(
        name="versioned",
        action="allow",
        subject=PolicySubject(agent_ids=["agent-1"]),
        resource=PolicyResource(tool_names=["weather.lookup"]),
        version=3,
    )

    assert policy.version == 3
