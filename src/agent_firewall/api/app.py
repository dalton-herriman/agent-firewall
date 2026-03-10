from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status

from agent_firewall.auth import AuthPrincipal, require_scope
from agent_firewall.config import Settings, get_settings
from agent_firewall.container import Container
from agent_firewall.management import ManagementService
from agent_firewall.models.audit import AuditLogEntry, AuditLogQuery
from agent_firewall.models.config import AdapterConfig, RuntimeConfig
from agent_firewall.models.policy import PolicyRevision, PolicyRule, PolicyValidationResult
from agent_firewall.models.tooling import ToolExecutionResult, ToolInvocationDecision, ToolInvocationRequest
from agent_firewall.observability import configure_telemetry, instrument_fastapi
from agent_firewall.service import FirewallService


async def get_container(request: Request) -> Container:
    return request.app.state.container


async def get_firewall_service(container: Container = Depends(get_container)) -> FirewallService:
    return container.firewall_service()


async def get_management_service(container: Container = Depends(get_container)) -> ManagementService:
    return container.management_service()


async def get_evaluate_principal(request: Request) -> AuthPrincipal:
    return require_scope(request, "evaluate")


async def get_management_principal(request: Request) -> AuthPrincipal:
    return require_scope(request, "manage")


async def get_audit_principal(request: Request) -> AuthPrincipal:
    return require_scope(request, "audit:read")


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
        principal: AuthPrincipal = Depends(get_evaluate_principal),
        firewall_service: FirewallService = Depends(get_firewall_service),
    ) -> ToolInvocationDecision:
        if payload.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
        if principal.project_ids and payload.project_id not in principal.project_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="project mismatch")
        return await firewall_service.evaluate(payload)

    @app.post(f"{settings.api_prefix}/tool-invocations/execute", response_model=ToolExecutionResult)
    async def execute_tool_invocation(
        payload: ToolInvocationRequest,
        principal: AuthPrincipal = Depends(get_evaluate_principal),
        firewall_service: FirewallService = Depends(get_firewall_service),
    ) -> ToolExecutionResult:
        if payload.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
        if principal.project_ids and payload.project_id not in principal.project_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="project mismatch")
        try:
            return await firewall_service.execute(payload)
        except LookupError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    @app.get(f"{settings.api_prefix}/policies", response_model=list[PolicyRule])
    async def list_policies(
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> list[PolicyRule]:
        return list(await management_service.list_policies(principal.tenant_id))

    @app.post(f"{settings.api_prefix}/policies", response_model=PolicyRule, status_code=status.HTTP_201_CREATED)
    async def create_policy(
        payload: PolicyRule,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> PolicyRule:
        if payload.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
        try:
            policy = await management_service.upsert_policy(payload)
            await management_service.record_management_event(
                tenant_id=principal.tenant_id,
                actor_id=principal.actor_id,
                action="policy.create",
                payload=policy.model_dump(mode="json"),
            )
            return policy
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    @app.get(f"{settings.api_prefix}/policies/{{policy_id}}", response_model=PolicyRule)
    async def get_policy(
        policy_id: str,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> PolicyRule:
        policy = await management_service.get_policy(policy_id)
        if policy is None or policy.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy not found")
        return policy

    @app.get(f"{settings.api_prefix}/policies/{{policy_id}}/revisions", response_model=list[PolicyRevision])
    async def list_policy_revisions(
        policy_id: str,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> list[PolicyRevision]:
        return list(await management_service.list_policy_revisions(principal.tenant_id, policy_id))

    @app.put(f"{settings.api_prefix}/policies/{{policy_id}}", response_model=PolicyRule)
    async def update_policy(
        policy_id: str,
        payload: PolicyRule,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> PolicyRule:
        if str(payload.id) != policy_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="policy id mismatch")
        if payload.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
        try:
            policy = await management_service.upsert_policy(payload)
            await management_service.record_management_event(
                tenant_id=principal.tenant_id,
                actor_id=principal.actor_id,
                action="policy.update",
                payload=policy.model_dump(mode="json"),
            )
            return policy
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    @app.post(f"{settings.api_prefix}/policies/validate", response_model=PolicyValidationResult)
    async def validate_policy(
        payload: PolicyRule,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> PolicyValidationResult:
        if payload.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
        return await management_service.validate_policy(payload)

    @app.delete(f"{settings.api_prefix}/policies/{{policy_id}}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_policy(
        policy_id: str,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> Response:
        policy = await management_service.get_policy(policy_id)
        if policy is None or policy.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy not found")
        deleted = await management_service.delete_policy(principal.tenant_id, policy_id)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy not found")
        await management_service.record_management_event(
            tenant_id=principal.tenant_id,
            actor_id=principal.actor_id,
            action="policy.delete",
            payload={"policy_id": policy_id},
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post(f"{settings.api_prefix}/policies/{{policy_id}}/publish", response_model=PolicyRule)
    async def publish_policy(
        policy_id: str,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> PolicyRule:
        policy = await management_service.publish_policy(principal.tenant_id, policy_id)
        if policy is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy not found")
        return policy

    @app.post(f"{settings.api_prefix}/policies/{{policy_id}}/rollback/{{version}}", response_model=PolicyRule)
    async def rollback_policy(
        policy_id: str,
        version: int,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> PolicyRule:
        policy = await management_service.rollback_policy(principal.tenant_id, policy_id, version)
        if policy is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy revision not found")
        return policy

    @app.get(f"{settings.api_prefix}/adapters", response_model=list[AdapterConfig])
    async def list_adapters(
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> list[AdapterConfig]:
        return list(await management_service.list_adapters(principal.tenant_id))

    @app.post(f"{settings.api_prefix}/adapters", response_model=AdapterConfig, status_code=status.HTTP_201_CREATED)
    async def create_adapter(
        payload: AdapterConfig,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> AdapterConfig:
        if payload.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
        adapter = await management_service.upsert_adapter(payload)
        await management_service.record_management_event(
            tenant_id=principal.tenant_id,
            actor_id=principal.actor_id,
            action="adapter.upsert",
            payload=adapter.model_dump(mode="json"),
        )
        return adapter

    @app.get(f"{settings.api_prefix}/adapters/{{tool_name}}", response_model=AdapterConfig)
    async def get_adapter(
        tool_name: str,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> AdapterConfig:
        adapter = await management_service.get_adapter(principal.tenant_id, tool_name)
        if adapter is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="adapter not found")
        return adapter

    @app.put(f"{settings.api_prefix}/adapters/{{tool_name}}", response_model=AdapterConfig)
    async def update_adapter(
        tool_name: str,
        payload: AdapterConfig,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> AdapterConfig:
        if payload.tool_name != tool_name:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tool name mismatch")
        if payload.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
        adapter = await management_service.upsert_adapter(payload)
        await management_service.record_management_event(
            tenant_id=principal.tenant_id,
            actor_id=principal.actor_id,
            action="adapter.update",
            payload=adapter.model_dump(mode="json"),
        )
        return adapter

    @app.delete(f"{settings.api_prefix}/adapters/{{tool_name}}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_adapter(
        tool_name: str,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> Response:
        deleted = await management_service.delete_adapter(principal.tenant_id, tool_name)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="adapter not found")
        await management_service.record_management_event(
            tenant_id=principal.tenant_id,
            actor_id=principal.actor_id,
            action="adapter.delete",
            payload={"tool_name": tool_name},
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get(f"{settings.api_prefix}/runtime-config", response_model=list[RuntimeConfig])
    async def list_runtime_configs(
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> list[RuntimeConfig]:
        return list(await management_service.list_configs(principal.tenant_id))

    @app.post(f"{settings.api_prefix}/runtime-config", response_model=RuntimeConfig, status_code=status.HTTP_201_CREATED)
    async def create_runtime_config(
        payload: RuntimeConfig,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> RuntimeConfig:
        if payload.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
        config = await management_service.upsert_config(payload)
        await management_service.record_management_event(
            tenant_id=principal.tenant_id,
            actor_id=principal.actor_id,
            action="runtime-config.upsert",
            payload=config.model_dump(mode="json"),
        )
        return config

    @app.get(f"{settings.api_prefix}/runtime-config/{{key}}", response_model=RuntimeConfig)
    async def get_runtime_config(
        key: str,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> RuntimeConfig:
        config = await management_service.get_config(principal.tenant_id, key)
        if config is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="runtime config not found")
        return config

    @app.put(f"{settings.api_prefix}/runtime-config/{{key}}", response_model=RuntimeConfig)
    async def update_runtime_config(
        key: str,
        payload: RuntimeConfig,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> RuntimeConfig:
        if payload.key != key:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="runtime config key mismatch")
        if payload.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
        config = await management_service.upsert_config(payload)
        await management_service.record_management_event(
            tenant_id=principal.tenant_id,
            actor_id=principal.actor_id,
            action="runtime-config.update",
            payload=config.model_dump(mode="json"),
        )
        return config

    @app.delete(f"{settings.api_prefix}/runtime-config/{{key}}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_runtime_config(
        key: str,
        principal: AuthPrincipal = Depends(get_management_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> Response:
        deleted = await management_service.delete_config(principal.tenant_id, key)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="runtime config not found")
        await management_service.record_management_event(
            tenant_id=principal.tenant_id,
            actor_id=principal.actor_id,
            action="runtime-config.delete",
            payload={"key": key},
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get(f"{settings.api_prefix}/audit-logs", response_model=list[AuditLogEntry])
    async def list_audit_logs(
        agent_id: str | None = None,
        tool_name: str | None = None,
        project_id: str | None = None,
        limit: int = 100,
        principal: AuthPrincipal = Depends(get_audit_principal),
        management_service: ManagementService = Depends(get_management_service),
    ) -> list[AuditLogEntry]:
        if principal.project_ids and project_id and project_id not in principal.project_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="project mismatch")
        return list(
            await management_service.list_audit_logs(
                AuditLogQuery(
                    tenant_id=principal.tenant_id,
                    project_id=project_id,
                    agent_id=agent_id,
                    tool_name=tool_name,
                    limit=limit,
                )
            )
        )

    return app
