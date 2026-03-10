from __future__ import annotations

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from agent_firewall.config import Settings
from agent_firewall.container import Container
from agent_firewall.models.audit import AuditLogQuery
from agent_firewall.models.config import AdapterConfig, ToolArgumentSpec
from agent_firewall.models.policy import PolicyCondition, PolicyResource, PolicyRule, PolicySubject
from agent_firewall.models.tooling import ToolInvocationRequest


def integration_enabled() -> bool:
    return bool(os.getenv("AGENT_FIREWALL_RUN_INTEGRATION"))


def integration_settings() -> Settings:
    database_url = os.getenv("AGENT_FIREWALL_TEST_DATABASE_URL")
    redis_url = os.getenv("AGENT_FIREWALL_TEST_REDIS_URL")
    if not database_url or not redis_url:
        raise RuntimeError("integration settings require AGENT_FIREWALL_TEST_DATABASE_URL and AGENT_FIREWALL_TEST_REDIS_URL")
    return Settings(
        app_env="integration",
        database_url=database_url,
        redis_url=redis_url,
        default_policy_mode="deny",
    )


def alembic_config(database_url: str) -> Config:
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


@pytest.mark.integration
@pytest.mark.asyncio
async def test_postgres_and_redis_backed_container_path() -> None:
    if not integration_enabled():
        pytest.skip("set AGENT_FIREWALL_RUN_INTEGRATION=1 to run persistence integration tests")

    settings = integration_settings()
    command.upgrade(alembic_config(settings.database_url), "head")
    container = Container.build(settings=settings, use_in_memory=False)
    try:
        health = await container.dependency_health()
        assert health.postgres is True
        assert health.redis is True

        management = container.management_service()
        await management.upsert_adapter(
            AdapterConfig(
                tenant_id="default",
                tool_name="weather.lookup",
                target_uri="https://example.com/weather",
                schema=[ToolArgumentSpec(name="city", value_type="string", required=True)],
            )
        )
        policy = await management.upsert_policy(
            PolicyRule(
                tenant_id="default",
                name="allow chicago weather",
                action="allow",
                subject=PolicySubject(agent_ids=["agent-int"]),
                resource=PolicyResource(tool_names=["weather.lookup"]),
                conditions=[PolicyCondition(field="tool_args.city", operator="eq", value="Chicago")],
                priority=1,
            )
        )

        decision = await container.firewall_service().evaluate(
            ToolInvocationRequest(
                tenant_id="default",
                agent_id="agent-int",
                tool_name="weather.lookup",
                tool_args={"city": "Chicago"},
            )
        )
        logs = await management.list_audit_logs(AuditLogQuery(agent_id="agent-int", limit=10))

        assert decision.allowed is True
        assert decision.matched_policy_id == str(policy.id)
        assert logs
    finally:
        await container.shutdown()
