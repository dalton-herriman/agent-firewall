from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from agent_firewall.models.audit import AuditLogEntry, AuditLogQuery
from agent_firewall.models.config import AdapterConfig, RuntimeConfig
from agent_firewall.models.policy import PolicyRule


class PolicyRepository(Protocol):
    async def list_rules_for_agent(self, tenant_id: str, agent_id: str) -> Sequence[PolicyRule]:
        ...

    async def list_policies(self, tenant_id: str) -> Sequence[PolicyRule]:
        ...

    async def get_policy(self, policy_id: str) -> PolicyRule | None:
        ...

    async def upsert_policy(self, policy: PolicyRule) -> PolicyRule:
        ...

    async def delete_policy(self, tenant_id: str, policy_id: str) -> bool:
        ...


class AuditLogRepository(Protocol):
    async def record(self, entry: AuditLogEntry) -> None:
        ...

    async def list_entries(self, query: AuditLogQuery) -> Sequence[AuditLogEntry]:
        ...


class AdapterRepository(Protocol):
    async def get_by_tool_name(self, tenant_id: str, tool_name: str) -> AdapterConfig | None:
        ...

    async def list_adapters(self, tenant_id: str) -> Sequence[AdapterConfig]:
        ...

    async def upsert_adapter(self, adapter: AdapterConfig) -> AdapterConfig:
        ...

    async def delete_adapter(self, tenant_id: str, tool_name: str) -> bool:
        ...


class RuntimeConfigRepository(Protocol):
    async def get(self, tenant_id: str, key: str) -> RuntimeConfig | None:
        ...

    async def list_configs(self, tenant_id: str) -> Sequence[RuntimeConfig]:
        ...

    async def upsert_config(self, config: RuntimeConfig) -> RuntimeConfig:
        ...

    async def delete_config(self, tenant_id: str, key: str) -> bool:
        ...
