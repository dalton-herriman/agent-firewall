from __future__ import annotations

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import async_sessionmaker

from agent_firewall.cache import InMemoryRateLimiter, RedisRateLimiter
from agent_firewall.config import Settings
from agent_firewall.executor import HttpToolExecutor
from agent_firewall.health import DependencyHealth, check_dependencies
from agent_firewall.management import ManagementService
from agent_firewall.repositories.memory import (
    InMemoryAdapterRepository,
    InMemoryAuditLogRepository,
    InMemoryPolicyRepository,
    InMemoryRuntimeConfigRepository,
)
from agent_firewall.repositories.postgres import (
    PostgresAdapterRepository,
    PostgresAuditLogRepository,
    PostgresPolicyRepository,
    PostgresRuntimeConfigRepository,
    create_engine,
)
from agent_firewall.service import FirewallService


class Container:
    def __init__(
        self,
        *,
        settings: Settings,
        policy_repository,
        audit_log_repository,
        adapter_repository,
        runtime_config_repository,
        rate_limiter,
        tool_executor=None,
        engine=None,
        redis: Redis | None = None,
    ) -> None:
        self.settings = settings
        self.policy_repository = policy_repository
        self.audit_log_repository = audit_log_repository
        self.adapter_repository = adapter_repository
        self.runtime_config_repository = runtime_config_repository
        self.rate_limiter = rate_limiter
        self.tool_executor = tool_executor
        self.engine = engine
        self.redis = redis
        self._firewall_service = FirewallService(
            settings=self.settings,
            policy_repository=self.policy_repository,
            audit_log_repository=self.audit_log_repository,
            adapter_repository=self.adapter_repository,
            rate_limiter=self.rate_limiter,
            tool_executor=self.tool_executor,
        )
        self._management_service = ManagementService(
            policy_repository=self.policy_repository,
            audit_log_repository=self.audit_log_repository,
            adapter_repository=self.adapter_repository,
            runtime_config_repository=self.runtime_config_repository,
        )

    @classmethod
    def build(cls, settings: Settings, use_in_memory: bool = False) -> "Container":
        if use_in_memory:
            return cls(
                settings=settings,
                policy_repository=InMemoryPolicyRepository(),
                audit_log_repository=InMemoryAuditLogRepository(),
                adapter_repository=InMemoryAdapterRepository(),
                runtime_config_repository=InMemoryRuntimeConfigRepository(),
                rate_limiter=InMemoryRateLimiter(),
                tool_executor=None,
            )

        engine = create_engine(settings.database_url)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        redis = Redis.from_url(settings.redis_url, decode_responses=True)
        return cls(
            settings=settings,
            policy_repository=PostgresPolicyRepository(session_factory),
            audit_log_repository=PostgresAuditLogRepository(session_factory),
            adapter_repository=PostgresAdapterRepository(session_factory),
            runtime_config_repository=PostgresRuntimeConfigRepository(session_factory),
            rate_limiter=RedisRateLimiter(redis),
            tool_executor=HttpToolExecutor(),
            engine=engine,
            redis=redis,
        )

    def firewall_service(self) -> FirewallService:
        return self._firewall_service

    def management_service(self) -> ManagementService:
        return self._management_service

    async def dependency_health(self) -> DependencyHealth:
        return await check_dependencies(self.engine, self.redis)

    async def shutdown(self) -> None:
        if self.redis is not None:
            await self.redis.aclose()
        if self.engine is not None:
            await self.engine.dispose()
