from __future__ import annotations

from collections.abc import Sequence

from agent_firewall.models.audit import AuditLogEntry, AuditLogQuery
from agent_firewall.models.config import AdapterConfig, RuntimeConfig
from agent_firewall.models.policy import PolicyRevision, PolicyRule
from agent_firewall.repositories.base import (
    AdapterRepository,
    AuditLogRepository,
    PolicyRepository,
    RuntimeConfigRepository,
)


class InMemoryPolicyRepository(PolicyRepository):
    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        self._rules = {str(rule.id): rule for rule in rules or []}
        self._revisions: dict[str, list[PolicyRevision]] = {}

    async def list_rules_for_agent(self, tenant_id: str, agent_id: str) -> Sequence[PolicyRule]:
        return [
            rule
            for rule in self._rules.values()
            if rule.tenant_id == tenant_id and rule.enabled and rule.subject.matches(agent_id)
        ]

    async def list_policies(self, tenant_id: str) -> Sequence[PolicyRule]:
        return [rule for rule in self._rules.values() if rule.tenant_id == tenant_id]

    async def get_policy(self, policy_id: str) -> PolicyRule | None:
        return self._rules.get(policy_id)

    async def upsert_policy(self, policy: PolicyRule) -> PolicyRule:
        self._rules[str(policy.id)] = policy
        return policy

    async def delete_policy(self, tenant_id: str, policy_id: str) -> bool:
        policy = self._rules.get(policy_id)
        if policy is None or policy.tenant_id != tenant_id:
            return False
        self._rules.pop(policy_id, None)
        return True

    async def list_policy_revisions(self, tenant_id: str, policy_id: str) -> Sequence[PolicyRevision]:
        return [revision for revision in self._revisions.get(policy_id, []) if revision.tenant_id == tenant_id]

    async def append_policy_revision(self, revision: PolicyRevision) -> None:
        self._revisions.setdefault(str(revision.policy_id), []).append(revision)


class InMemoryAuditLogRepository(AuditLogRepository):
    def __init__(self) -> None:
        self.entries: list[AuditLogEntry] = []

    async def record(self, entry: AuditLogEntry) -> None:
        self.entries.append(entry)

    async def list_entries(self, query: AuditLogQuery) -> Sequence[AuditLogEntry]:
        entries = self.entries
        if query.tenant_id:
            entries = [entry for entry in entries if entry.tenant_id == query.tenant_id]
        if query.agent_id:
            entries = [entry for entry in entries if entry.agent_id == query.agent_id]
        if query.tool_name:
            entries = [entry for entry in entries if entry.tool_name == query.tool_name]
        return list(reversed(entries))[: query.limit]


class InMemoryAdapterRepository(AdapterRepository):
    def __init__(self, configs: list[AdapterConfig] | None = None) -> None:
        self._configs = {(config.tenant_id, config.tool_name): config for config in configs or []}

    async def get_by_tool_name(self, tenant_id: str, tool_name: str) -> AdapterConfig | None:
        return self._configs.get((tenant_id, tool_name))

    async def list_adapters(self, tenant_id: str) -> Sequence[AdapterConfig]:
        return [config for config in self._configs.values() if config.tenant_id == tenant_id]

    async def upsert_adapter(self, adapter: AdapterConfig) -> AdapterConfig:
        self._configs[(adapter.tenant_id, adapter.tool_name)] = adapter
        return adapter

    async def delete_adapter(self, tenant_id: str, tool_name: str) -> bool:
        return self._configs.pop((tenant_id, tool_name), None) is not None


class InMemoryRuntimeConfigRepository(RuntimeConfigRepository):
    def __init__(self, configs: list[RuntimeConfig] | None = None) -> None:
        self._configs = {(config.tenant_id, config.key): config for config in configs or []}

    async def get(self, tenant_id: str, key: str) -> RuntimeConfig | None:
        return self._configs.get((tenant_id, key))

    async def list_configs(self, tenant_id: str) -> Sequence[RuntimeConfig]:
        return [config for config in self._configs.values() if config.tenant_id == tenant_id]

    async def upsert_config(self, config: RuntimeConfig) -> RuntimeConfig:
        self._configs[(config.tenant_id, config.key)] = config
        return config

    async def delete_config(self, tenant_id: str, key: str) -> bool:
        return self._configs.pop((tenant_id, key), None) is not None
