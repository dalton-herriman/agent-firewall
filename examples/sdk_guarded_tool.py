from __future__ import annotations

import asyncio

from agent_firewall.cache import InMemoryRateLimiter
from agent_firewall.models.config import AdapterConfig, ToolArgumentSpec
from agent_firewall.models.policy import PolicyCondition, PolicyResource, PolicyRule, PolicySubject
from agent_firewall.repositories.memory import (
    InMemoryAdapterRepository,
    InMemoryAuditLogRepository,
    InMemoryPolicyRepository,
)
from agent_firewall.sdk import AgentFirewallSDK
from agent_firewall.service import FirewallService
from agent_firewall.config import Settings


async def main() -> None:
    sdk = AgentFirewallSDK(
        FirewallService(
            settings=Settings(app_env="example"),
            policy_repository=InMemoryPolicyRepository(
                [
                    PolicyRule(
                        tenant_id="default",
                        name="allow chicago weather",
                        action="allow",
                        subject=PolicySubject(agent_ids=["demo-agent"]),
                        resource=PolicyResource(tool_names=["weather.lookup"]),
                        conditions=[PolicyCondition(field="tool_args.city", operator="eq", value="Chicago")],
                    )
                ]
            ),
            audit_log_repository=InMemoryAuditLogRepository(),
            adapter_repository=InMemoryAdapterRepository(
                [
                    AdapterConfig(
                        tenant_id="default",
                        tool_name="weather.lookup",
                        target_uri="https://example.com/weather",
                        schema=[ToolArgumentSpec(name="city", value_type="string", required=True)],
                    )
                ]
            ),
            rate_limiter=InMemoryRateLimiter(),
        )
    )

    result = await sdk.call_tool(
        agent_id="demo-agent",
        tool_name="weather.lookup",
        tool_args={"city": "Chicago"},
        callback=lambda: {"forecast": "clear"},
    )
    print(result)


if __name__ == "__main__":
    asyncio.run(main())

