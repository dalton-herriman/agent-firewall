import pytest
from httpx import ASGITransport, AsyncClient

from agent_firewall.api.app import create_app
from agent_firewall.config import Settings


@pytest.mark.asyncio
async def test_healthcheck() -> None:
    app = create_app(Settings(app_env="test"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
