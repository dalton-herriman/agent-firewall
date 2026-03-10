import pytest
from httpx import ASGITransport, AsyncClient

from agent_firewall.api.app import create_app
from agent_firewall.cache import InMemoryRateLimiter
from agent_firewall.config import Settings
from agent_firewall.container import Container
from agent_firewall.models.config import AdapterConfig, RuntimeConfig, ToolArgumentSpec
from agent_firewall.models.policy import PolicyCondition, PolicyResource, PolicyRule, PolicySubject
from agent_firewall.repositories.memory import (
    InMemoryAdapterRepository,
    InMemoryAuditLogRepository,
    InMemoryPolicyRepository,
    InMemoryRuntimeConfigRepository,
)


def build_test_container() -> Container:
    return Container(
        settings=Settings(app_env="test", default_policy_mode="deny"),
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
                    target_uri="https://example.com/weather",
                    schema=[ToolArgumentSpec(name="city", value_type="string", required=True)],
                )
            ]
        ),
        runtime_config_repository=InMemoryRuntimeConfigRepository(
            [RuntimeConfig(key="server", value={"mode": "test"})]
        ),
        rate_limiter=InMemoryRateLimiter(),
    )


@pytest.mark.asyncio
async def test_healthcheck() -> None:
    app = create_app(Settings(app_env="test"), container=build_test_container())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_evaluate_tool_invocation_and_audit_log_flow() -> None:
    app = create_app(Settings(app_env="test"), container=build_test_container())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post(
            "/v1/tool-invocations/evaluate",
            json={
                "agent_id": "agent-1",
                "action": "invoke",
                "tool_name": "weather.lookup",
                "tool_args": {"city": "Chicago"},
                "metadata": {"trace_id": "trace-1"},
            },
        )
        audit_response = await client.get("/v1/audit-logs")

    assert response.status_code == 200
    assert response.json()["allowed"] is True
    assert audit_response.status_code == 200
    assert audit_response.json()[0]["tool_name"] == "weather.lookup"


@pytest.mark.asyncio
async def test_policy_adapter_and_runtime_config_crud() -> None:
    app = create_app(Settings(app_env="test"), container=build_test_container())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        create_policy = await client.post(
            "/v1/policies",
            json={
                "name": "deny destructive tools",
                "action": "deny",
                "subject": {"agent_ids": ["agent-2"]},
                "resource": {"tool_names": ["filesystem.*"]},
                "conditions": [],
                "priority": 5,
                "enabled": True,
            },
        )
        list_policies = await client.get("/v1/policies")
        create_adapter = await client.post(
            "/v1/adapters",
            json={
                "tool_name": "filesystem.delete",
                "target_uri": "https://example.com/fs",
                "timeout_seconds": 10,
                "schema": [{"name": "path", "value_type": "string", "required": True, "allowed_values": []}],
            },
        )
        create_runtime_config = await client.post(
            "/v1/runtime-config",
            json={"key": "policy-mode", "value": {"default": "deny"}},
        )

    assert create_policy.status_code == 201
    assert list_policies.status_code == 200
    assert len(list_policies.json()) == 2
    assert create_adapter.status_code == 201
    assert create_runtime_config.status_code == 201
