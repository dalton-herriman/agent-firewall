from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status

from agent_firewall.config import Settings, get_settings
from agent_firewall.container import Container
from agent_firewall.management import ManagementService
from agent_firewall.models.audit import AuditLogEntry, AuditLogQuery
from agent_firewall.models.config import AdapterConfig, RuntimeConfig
from agent_firewall.models.policy import PolicyRule, PolicyValidationResult
from agent_firewall.models.tooling import ToolExecutionResult, ToolInvocationDecision, ToolInvocationRequest
from agent_firewall.observability import configure_telemetry, instrument_fastapi
from agent_firewall.service import FirewallService


async def get_container(request: Request) -> Container:
    return request.app.state.container


async def get_firewall_service(container: Container = Depends(get_container)) -> FirewallService:
    return container.firewall_service()


async def get_management_service(container: Container = Depends(get_container)) -> ManagementService:
    return container.management_service()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    if settings.app_env != "test":
        configure_telemetry(settings)
    yield
    await app.state.container.shutdown()


def create_app(settings: Settings | None = None, container: Container | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)
    app.state.settings = settings
    app.state.container = container or Container.build(settings=settings, use_in_memory=settings.app_env == "test")
    if settings.app_env != "test":
        instrument_fastapi(app)

    @app.get("/health")
    async def healthcheck() -> dict[str, str]:
        return {"status": "ok", "service": settings.app_name}

    @app.get(f"{settings.api_prefix}/health/dependencies")
    async def dependency_health(container: Container = Depends(get_container)) -> dict[str, bool]:
        health = await container.dependency_health()
        return {"postgres": health.postgres, "redis": health.redis}

    @app.post(f"{settings.api_prefix}/tool-invocations/evaluate", response_model=ToolInvocationDecision)
    async def evaluate_tool_invocation(
        payload: ToolInvocationRequest,
        firewall_service: FirewallService = Depends(get_firewall_service),
    ) -> ToolInvocationDecision:
        return await firewall_service.evaluate(payload)

    @app.post(f"{settings.api_prefix}/tool-invocations/execute", response_model=ToolExecutionResult)
    async def execute_tool_invocation(
        payload: ToolInvocationRequest,
        firewall_service: FirewallService = Depends(get_firewall_service),
    ) -> ToolExecutionResult:
        try:
            return await firewall_service.execute(payload)
        except LookupError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    @app.get(f"{settings.api_prefix}/policies", response_model=list[PolicyRule])
    async def list_policies(management_service: ManagementService = Depends(get_management_service)) -> list[PolicyRule]:
        return list(await management_service.list_policies())

    @app.post(f"{settings.api_prefix}/policies", response_model=PolicyRule, status_code=status.HTTP_201_CREATED)
    async def create_policy(
        payload: PolicyRule,
        management_service: ManagementService = Depends(get_management_service),
    ) -> PolicyRule:
        try:
            return await management_service.upsert_policy(payload)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    @app.get(f"{settings.api_prefix}/policies/{{policy_id}}", response_model=PolicyRule)
    async def get_policy(policy_id: str, management_service: ManagementService = Depends(get_management_service)) -> PolicyRule:
        policy = await management_service.get_policy(policy_id)
        if policy is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy not found")
        return policy

    @app.put(f"{settings.api_prefix}/policies/{{policy_id}}", response_model=PolicyRule)
    async def update_policy(
        policy_id: str,
        payload: PolicyRule,
        management_service: ManagementService = Depends(get_management_service),
    ) -> PolicyRule:
        if str(payload.id) != policy_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="policy id mismatch")
        try:
            return await management_service.upsert_policy(payload)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    @app.post(f"{settings.api_prefix}/policies/validate", response_model=PolicyValidationResult)
    async def validate_policy(
        payload: PolicyRule,
        management_service: ManagementService = Depends(get_management_service),
    ) -> PolicyValidationResult:
        return await management_service.validate_policy(payload)

    @app.delete(f"{settings.api_prefix}/policies/{{policy_id}}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_policy(
        policy_id: str,
        management_service: ManagementService = Depends(get_management_service),
    ) -> Response:
        deleted = await management_service.delete_policy(policy_id)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get(f"{settings.api_prefix}/adapters", response_model=list[AdapterConfig])
    async def list_adapters(management_service: ManagementService = Depends(get_management_service)) -> list[AdapterConfig]:
        return list(await management_service.list_adapters())

    @app.post(f"{settings.api_prefix}/adapters", response_model=AdapterConfig, status_code=status.HTTP_201_CREATED)
    async def create_adapter(
        payload: AdapterConfig,
        management_service: ManagementService = Depends(get_management_service),
    ) -> AdapterConfig:
        return await management_service.upsert_adapter(payload)

    @app.get(f"{settings.api_prefix}/adapters/{{tool_name}}", response_model=AdapterConfig)
    async def get_adapter(tool_name: str, management_service: ManagementService = Depends(get_management_service)) -> AdapterConfig:
        adapter = await management_service.get_adapter(tool_name)
        if adapter is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="adapter not found")
        return adapter

    @app.put(f"{settings.api_prefix}/adapters/{{tool_name}}", response_model=AdapterConfig)
    async def update_adapter(
        tool_name: str,
        payload: AdapterConfig,
        management_service: ManagementService = Depends(get_management_service),
    ) -> AdapterConfig:
        if payload.tool_name != tool_name:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tool name mismatch")
        return await management_service.upsert_adapter(payload)

    @app.delete(f"{settings.api_prefix}/adapters/{{tool_name}}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_adapter(
        tool_name: str,
        management_service: ManagementService = Depends(get_management_service),
    ) -> Response:
        deleted = await management_service.delete_adapter(tool_name)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="adapter not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get(f"{settings.api_prefix}/runtime-config", response_model=list[RuntimeConfig])
    async def list_runtime_configs(management_service: ManagementService = Depends(get_management_service)) -> list[RuntimeConfig]:
        return list(await management_service.list_configs())

    @app.post(f"{settings.api_prefix}/runtime-config", response_model=RuntimeConfig, status_code=status.HTTP_201_CREATED)
    async def create_runtime_config(
        payload: RuntimeConfig,
        management_service: ManagementService = Depends(get_management_service),
    ) -> RuntimeConfig:
        return await management_service.upsert_config(payload)

    @app.get(f"{settings.api_prefix}/runtime-config/{{key}}", response_model=RuntimeConfig)
    async def get_runtime_config(key: str, management_service: ManagementService = Depends(get_management_service)) -> RuntimeConfig:
        config = await management_service.get_config(key)
        if config is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="runtime config not found")
        return config

    @app.put(f"{settings.api_prefix}/runtime-config/{{key}}", response_model=RuntimeConfig)
    async def update_runtime_config(
        key: str,
        payload: RuntimeConfig,
        management_service: ManagementService = Depends(get_management_service),
    ) -> RuntimeConfig:
        if payload.key != key:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="runtime config key mismatch")
        return await management_service.upsert_config(payload)

    @app.delete(f"{settings.api_prefix}/runtime-config/{{key}}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_runtime_config(
        key: str,
        management_service: ManagementService = Depends(get_management_service),
    ) -> Response:
        deleted = await management_service.delete_config(key)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="runtime config not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get(f"{settings.api_prefix}/audit-logs", response_model=list[AuditLogEntry])
    async def list_audit_logs(
        agent_id: str | None = None,
        tool_name: str | None = None,
        limit: int = 100,
        management_service: ManagementService = Depends(get_management_service),
    ) -> list[AuditLogEntry]:
        return list(await management_service.list_audit_logs(AuditLogQuery(agent_id=agent_id, tool_name=tool_name, limit=limit)))

    return app
