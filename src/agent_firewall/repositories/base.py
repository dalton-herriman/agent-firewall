from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from agent_firewall.models.audit import AuditLogEntry
from agent_firewall.models.config import AdapterConfig, RuntimeConfig
from agent_firewall.models.policy import PolicyRule


class PolicyRepository(Protocol):
    async def list_rules_for_agent(self, agent_id: str) -> Sequence[PolicyRule]:
        ...


class AuditLogRepository(Protocol):
    async def record(self, entry: AuditLogEntry) -> None:
        ...


class AdapterRepository(Protocol):
    async def get_by_tool_name(self, tool_name: str) -> AdapterConfig | None:
        ...


class RuntimeConfigRepository(Protocol):
    async def get(self, key: str) -> RuntimeConfig | None:
        ...

