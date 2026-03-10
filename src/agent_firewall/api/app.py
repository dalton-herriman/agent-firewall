from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from agent_firewall.config import Settings, get_settings
from agent_firewall.container import Container
from agent_firewall.models.tooling import ToolInvocationDecision, ToolInvocationRequest
from agent_firewall.observability import configure_telemetry, instrument_fastapi
from agent_firewall.service import FirewallService


async def get_container(settings: Settings = Depends(get_settings)) -> Container:
    return Container(settings=settings, use_in_memory=settings.app_env == "test")


async def get_firewall_service(container: Container = Depends(get_container)) -> FirewallService:
    return container.firewall_service()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    if settings.app_env != "test":
        configure_telemetry(settings)
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)
    app.state.settings = settings
    if settings.app_env != "test":
        instrument_fastapi(app)

    @app.get("/health")
    async def healthcheck() -> dict[str, str]:
        return {"status": "ok", "service": settings.app_name}

    @app.post(f"{settings.api_prefix}/tool-invocations/evaluate", response_model=ToolInvocationDecision)
    async def evaluate_tool_invocation(
        payload: ToolInvocationRequest,
        firewall_service: FirewallService = Depends(get_firewall_service),
    ) -> ToolInvocationDecision:
        return await firewall_service.evaluate(payload)

    return app
