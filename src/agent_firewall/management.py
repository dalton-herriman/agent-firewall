from __future__ import annotations

from collections.abc import Sequence

from agent_firewall.models.audit import AuditLogEntry, AuditLogQuery
from agent_firewall.models.config import AdapterConfig, RuntimeConfig
from agent_firewall.models.policy import PolicyRule
from agent_firewall.repositories.base import (
    AdapterRepository,
    AuditLogRepository,
    PolicyRepository,
    RuntimeConfigRepository,
)


class ManagementService:
    def __init__(
        self,
        policy_repository: PolicyRepository,
        audit_log_repository: AuditLogRepository,
        adapter_repository: AdapterRepository,
        runtime_config_repository: RuntimeConfigRepository,
    ) -> None:
        self._policy_repository = policy_repository
        self._audit_log_repository = audit_log_repository
        self._adapter_repository = adapter_repository
        self._runtime_config_repository = runtime_config_repository

    async def list_policies(self) -> Sequence[PolicyRule]:
        return await self._policy_repository.list_policies()

    async def get_policy(self, policy_id: str) -> PolicyRule | None:
        return await self._policy_repository.get_policy(policy_id)

    async def upsert_policy(self, policy: PolicyRule) -> PolicyRule:
        return await self._policy_repository.upsert_policy(policy)

    async def delete_policy(self, policy_id: str) -> bool:
        return await self._policy_repository.delete_policy(policy_id)

    async def list_adapters(self) -> Sequence[AdapterConfig]:
        return await self._adapter_repository.list_adapters()

    async def get_adapter(self, tool_name: str) -> AdapterConfig | None:
        return await self._adapter_repository.get_by_tool_name(tool_name)

    async def upsert_adapter(self, adapter: AdapterConfig) -> AdapterConfig:
        return await self._adapter_repository.upsert_adapter(adapter)

    async def delete_adapter(self, tool_name: str) -> bool:
        return await self._adapter_repository.delete_adapter(tool_name)

    async def list_configs(self) -> Sequence[RuntimeConfig]:
        return await self._runtime_config_repository.list_configs()

    async def get_config(self, key: str) -> RuntimeConfig | None:
        return await self._runtime_config_repository.get(key)

    async def upsert_config(self, config: RuntimeConfig) -> RuntimeConfig:
        return await self._runtime_config_repository.upsert_config(config)

    async def delete_config(self, key: str) -> bool:
        return await self._runtime_config_repository.delete_config(key)

    async def list_audit_logs(self, query: AuditLogQuery) -> Sequence[AuditLogEntry]:
        return await self._audit_log_repository.list_entries(query)
