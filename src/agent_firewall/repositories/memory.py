from __future__ import annotations

from collections.abc import Sequence

from agent_firewall.models.audit import AuditLogEntry
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
        self._rules = rules or []

    async def list_rules_for_agent(self, agent_id: str) -> Sequence[PolicyRule]:
        return self._rules


class InMemoryAuditLogRepository(AuditLogRepository):
    def __init__(self) -> None:
        self.entries: list[AuditLogEntry] = []

    async def record(self, entry: AuditLogEntry) -> None:
        self.entries.append(entry)


class InMemoryAdapterRepository(AdapterRepository):
    def __init__(self, configs: list[AdapterConfig] | None = None) -> None:
        self._configs = {config.tool_name: config for config in configs or []}

    async def get_by_tool_name(self, tool_name: str) -> AdapterConfig | None:
        return self._configs.get(tool_name)


class InMemoryRuntimeConfigRepository(RuntimeConfigRepository):
    def __init__(self, configs: list[RuntimeConfig] | None = None) -> None:
        self._configs = {config.key: config for config in configs or []}

    async def get(self, key: str) -> RuntimeConfig | None:
        return self._configs.get(key)

