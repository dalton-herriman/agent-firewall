from __future__ import annotations

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import async_sessionmaker

from agent_firewall.cache import InMemoryRateLimiter, RedisRateLimiter
from agent_firewall.config import Settings
from agent_firewall.repositories.memory import (
    InMemoryAdapterRepository,
    InMemoryAuditLogRepository,
    InMemoryPolicyRepository,
)
from agent_firewall.repositories.postgres import (
    PostgresAdapterRepository,
    PostgresAuditLogRepository,
    PostgresPolicyRepository,
    create_engine,
)
from agent_firewall.service import FirewallService


class Container:
    def __init__(self, settings: Settings, use_in_memory: bool = False) -> None:
        self.settings = settings
        self.use_in_memory = use_in_memory

    def firewall_service(self) -> FirewallService:
        if self.use_in_memory:
            return FirewallService(
                settings=self.settings,
                policy_repository=InMemoryPolicyRepository(),
                audit_log_repository=InMemoryAuditLogRepository(),
                adapter_repository=InMemoryAdapterRepository(),
                rate_limiter=InMemoryRateLimiter(),
            )

        engine = create_engine(self.settings.database_url)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        redis = Redis.from_url(self.settings.redis_url, decode_responses=True)
        return FirewallService(
            settings=self.settings,
            policy_repository=PostgresPolicyRepository(session_factory),
            audit_log_repository=PostgresAuditLogRepository(session_factory),
            adapter_repository=PostgresAdapterRepository(session_factory),
            rate_limiter=RedisRateLimiter(redis),
        )

