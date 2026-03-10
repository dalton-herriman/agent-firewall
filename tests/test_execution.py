import pytest

from agent_firewall.cache import InMemoryRateLimiter
from agent_firewall.config import Settings
from agent_firewall.container import Container
from agent_firewall.models.config import AdapterConfig, ToolArgumentSpec
from agent_firewall.models.policy import PolicyCondition, PolicyResource, PolicyRule, PolicySubject
from agent_firewall.models.tooling import ToolExecutionResult, ToolInvocationRequest
from agent_firewall.repositories.memory import (
    InMemoryAdapterRepository,
    InMemoryAuditLogRepository,
    InMemoryPolicyRepository,
    InMemoryRuntimeConfigRepository,
)


class StubExecutor:
    async def execute(self, *, adapter, request, decision):
        return ToolExecutionResult(
            tool_name=request.tool_name,
            status="executed",
            output={"adapter": adapter.target_uri, "city": request.tool_args["city"]},
            decision=decision,
        )


def build_container() -> Container:
    return Container(
        settings=Settings(app_env="test", default_policy_mode="deny", server_broker_enabled=True),
        policy_repository=InMemoryPolicyRepository(
            [
                PolicyRule(
                    name="allow chicago weather",
                    action="allow",
                    subject=PolicySubject(agent_ids=["agent-1"]),
                    resource=PolicyResource(tool_names=["weather.lookup"]),
                    conditions=[PolicyCondition(field="tool_args.city", operator="eq", value="Chicago")],
                    priority=1,
                )
            ]
        ),
        audit_log_repository=InMemoryAuditLogRepository(),
        adapter_repository=InMemoryAdapterRepository(
            [
                AdapterConfig(
                    tool_name="weather.lookup",
                    target_uri="https://tools.local/weather",
                    schema=[ToolArgumentSpec(name="city", value_type="string", required=True)],
                )
            ]
        ),
        runtime_config_repository=InMemoryRuntimeConfigRepository(),
        rate_limiter=InMemoryRateLimiter(),
        tool_executor=StubExecutor(),
    )


@pytest.mark.asyncio
async def test_execute_dispatches_allowed_tool_call() -> None:
    result = await build_container().firewall_service().execute(
        ToolInvocationRequest(agent_id="agent-1", tool_name="weather.lookup", tool_args={"city": "Chicago"})
    )

    assert result.status == "executed"
    assert result.output["city"] == "Chicago"


@pytest.mark.asyncio
async def test_execute_blocks_denied_tool_call() -> None:
    with pytest.raises(PermissionError):
        await build_container().firewall_service().execute(
            ToolInvocationRequest(agent_id="agent-1", tool_name="weather.lookup", tool_args={"city": "Austin"})
        )
