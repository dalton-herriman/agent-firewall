from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import JSON, Boolean, Integer, String, Text, select
from sqlalchemy.ext.asyncio import AsyncAttrs, AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from agent_firewall.models.audit import AuditLogEntry
from agent_firewall.models.config import AdapterConfig, RuntimeConfig
from agent_firewall.models.policy import PolicyCondition, PolicyRule
from agent_firewall.repositories.base import (
    AdapterRepository,
    AuditLogRepository,
    PolicyRepository,
    RuntimeConfigRepository,
)


class Base(AsyncAttrs, DeclarativeBase):
    pass


class PolicyRuleRow(Base):
    __tablename__ = "policy_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(200), index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text(), nullable=True)
    action: Mapped[str] = mapped_column(String(10))
    tool: Mapped[str] = mapped_column(String(200), index=True)
    conditions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class AuditLogRow(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(200), index=True)
    tool_name: Mapped[str] = mapped_column(String(200), index=True)
    decision: Mapped[str] = mapped_column(String(10))
    reason: Mapped[str] = mapped_column(String(500))
    request_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class AdapterConfigRow(Base):
    __tablename__ = "adapter_configs"

    tool_name: Mapped[str] = mapped_column(String(200), primary_key=True)
    target_uri: Mapped[str] = mapped_column(Text())
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    input_schema: Mapped[dict[str, Any]] = mapped_column("schema", JSON, default=dict)


class RuntimeConfigRow(Base):
    __tablename__ = "runtime_configs"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


def create_engine(database_url: str) -> AsyncEngine:
    return create_async_engine(database_url, future=True)


class PostgresPolicyRepository(PolicyRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def list_rules_for_agent(self, agent_id: str) -> Sequence[PolicyRule]:
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(PolicyRuleRow).where(PolicyRuleRow.agent_id == agent_id, PolicyRuleRow.enabled.is_(True))
            )
            return [
                PolicyRule(
                    id=row.id,
                    name=row.name,
                    description=row.description,
                    action=row.action,
                    tool=row.tool,
                    conditions=[PolicyCondition.model_validate(item) for item in row.conditions],
                    priority=row.priority,
                    enabled=row.enabled,
                )
                for row in rows
            ]


class PostgresAuditLogRepository(AuditLogRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def record(self, entry: AuditLogEntry) -> None:
        async with self._session_factory() as session:
            session.add(
                AuditLogRow(
                    id=str(entry.id),
                    agent_id=entry.agent_id,
                    tool_name=entry.tool_name,
                    decision=entry.decision,
                    reason=entry.reason,
                    request_payload=entry.request_payload,
                    created_at=entry.created_at,
                )
            )
            await session.commit()


class PostgresAdapterRepository(AdapterRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def get_by_tool_name(self, tool_name: str) -> AdapterConfig | None:
        async with self._session_factory() as session:
            row = await session.get(AdapterConfigRow, tool_name)
            if row is None:
                return None
            return AdapterConfig(
                tool_name=row.tool_name,
                target_uri=row.target_uri,
                timeout_seconds=row.timeout_seconds,
                schema=row.input_schema,
            )


class PostgresRuntimeConfigRepository(RuntimeConfigRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def get(self, key: str) -> RuntimeConfig | None:
        async with self._session_factory() as session:
            row = await session.get(RuntimeConfigRow, key)
            if row is None:
                return None
            return RuntimeConfig(key=row.key, value=row.value)
