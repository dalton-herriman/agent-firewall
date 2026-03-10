from __future__ import annotations

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from agent_firewall.api.app import create_app
from agent_firewall.config import ApiKeyConfig, Settings
from agent_firewall.container import Container


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
        auth_enabled=True,
        api_keys=[
            ApiKeyConfig(
                key_id="integration-admin",
                key="integration-key",
                actor_id="integration-admin",
                tenant_id="default",
                roles=["admin"],
                scopes=[],
                project_ids=["project-a"],
            )
        ],
    )


def alembic_config(database_url: str) -> Config:
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_stack_server_path(monkeypatch) -> None:
    if not integration_enabled():
        pytest.skip("set AGENT_FIREWALL_RUN_INTEGRATION=1 to run full-stack integration tests")

    settings = integration_settings()
    command.upgrade(alembic_config(settings.database_url), "head")

    class Response:
        status_code = 200
        content = b'{"status":"ok"}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "ok"}

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr("agent_firewall.executor.httpx.AsyncClient", Client)

    container = Container.build(settings=settings, use_in_memory=False)
    app = create_app(settings=settings, container=container)
    headers = {"x-agent-firewall-key": "integration-key"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        adapter = await client.post(
            "/v1/adapters",
            json={
                "tenant_id": "default",
                "tool_name": "weather.lookup",
                "target_uri": "https://example.com/weather",
                "timeout_seconds": 10,
                "schema": [{"name": "city", "value_type": "string", "required": True, "allowed_values": []}],
            },
            headers=headers,
        )
        policy = await client.post(
            "/v1/policies",
            json={
                "tenant_id": "default",
                "name": "allow weather",
                "action": "allow",
                "operation": "invoke",
                "subject": {"agent_ids": ["agent-int"]},
                "resource": {"tool_names": ["weather.lookup"]},
                "conditions": [{"field": "tool_args.city", "operator": "eq", "value": "Chicago"}],
                "priority": 1,
                "version": 1,
                "status": "published",
                "enabled": True,
            },
            headers=headers,
        )
        execute = await client.post(
            "/v1/tool-invocations/execute",
            json={
                "tenant_id": "default",
                "project_id": "project-a",
                "agent_id": "agent-int",
                "tool_name": "weather.lookup",
                "tool_args": {"city": "Chicago"},
                "metadata": {"idempotency_key": "integration-1"},
            },
            headers=headers,
        )

    assert adapter.status_code == 201
    assert policy.status_code == 201
    assert execute.status_code == 200
    assert execute.json()["status"] == "executed"
