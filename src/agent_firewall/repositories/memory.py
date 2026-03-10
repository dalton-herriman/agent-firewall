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


class InMemoryPolicyRepository(PolicyRepository):
    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        self._rules = {str(rule.id): rule for rule in rules or []}

    async def list_rules_for_agent(self, agent_id: str) -> Sequence[PolicyRule]:
        return [rule for rule in self._rules.values() if rule.enabled and rule.subject.matches(agent_id)]

    async def list_policies(self) -> Sequence[PolicyRule]:
        return list(self._rules.values())

    async def get_policy(self, policy_id: str) -> PolicyRule | None:
        return self._rules.get(policy_id)

    async def upsert_policy(self, policy: PolicyRule) -> PolicyRule:
        self._rules[str(policy.id)] = policy
        return policy

    async def delete_policy(self, policy_id: str) -> bool:
        return self._rules.pop(policy_id, None) is not None


class InMemoryAuditLogRepository(AuditLogRepository):
    def __init__(self) -> None:
        self.entries: list[AuditLogEntry] = []

    async def record(self, entry: AuditLogEntry) -> None:
        self.entries.append(entry)

    async def list_entries(self, query: AuditLogQuery) -> Sequence[AuditLogEntry]:
        entries = self.entries
        if query.agent_id:
            entries = [entry for entry in entries if entry.agent_id == query.agent_id]
        if query.tool_name:
            entries = [entry for entry in entries if entry.tool_name == query.tool_name]
        return list(reversed(entries))[: query.limit]


class InMemoryAdapterRepository(AdapterRepository):
    def __init__(self, configs: list[AdapterConfig] | None = None) -> None:
        self._configs = {config.tool_name: config for config in configs or []}

    async def get_by_tool_name(self, tool_name: str) -> AdapterConfig | None:
        return self._configs.get(tool_name)

    async def list_adapters(self) -> Sequence[AdapterConfig]:
        return list(self._configs.values())

    async def upsert_adapter(self, adapter: AdapterConfig) -> AdapterConfig:
        self._configs[adapter.tool_name] = adapter
        return adapter

    async def delete_adapter(self, tool_name: str) -> bool:
        return self._configs.pop(tool_name, None) is not None


class InMemoryRuntimeConfigRepository(RuntimeConfigRepository):
    def __init__(self, configs: list[RuntimeConfig] | None = None) -> None:
        self._configs = {config.key: config for config in configs or []}

    async def get(self, key: str) -> RuntimeConfig | None:
        return self._configs.get(key)

    async def list_configs(self) -> Sequence[RuntimeConfig]:
        return list(self._configs.values())

    async def upsert_config(self, config: RuntimeConfig) -> RuntimeConfig:
        self._configs[config.key] = config
        return config

    async def delete_config(self, key: str) -> bool:
        return self._configs.pop(key, None) is not None
