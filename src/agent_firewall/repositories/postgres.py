from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import JSON, Boolean, Integer, String, Text, delete, desc, select
from sqlalchemy.ext.asyncio import AsyncAttrs, AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from agent_firewall.models.audit import AuditLogEntry, AuditLogQuery
from agent_firewall.models.config import AdapterConfig, RuntimeConfig, ToolArgumentSpec
from agent_firewall.models.policy import PolicyCondition, PolicyResource, PolicyRule, PolicySubject
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
    effect: Mapped[str] = mapped_column("action", String(10))
    tool: Mapped[str] = mapped_column(String(200), index=True)
    subject_agent_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    invocation_action: Mapped[str] = mapped_column("invocation_action", String(50), default="invoke")
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
    matched_policy_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    request_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class AdapterConfigRow(Base):
    __tablename__ = "adapter_configs"

    tool_name: Mapped[str] = mapped_column(String(200), primary_key=True)
    target_uri: Mapped[str] = mapped_column(Text())
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    input_schema: Mapped[list[dict[str, Any]]] = mapped_column("schema", JSON, default=list)


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
                    effect=row.effect,
                    operation=row.invocation_action,
                    subject=PolicySubject(agent_ids=row.subject_agent_ids),
                    resource=PolicyResource(tool_names=[row.tool]),
                    conditions=[PolicyCondition.model_validate(item) for item in row.conditions],
                    priority=row.priority,
                    enabled=row.enabled,
                )
                for row in rows
            ]

    async def list_policies(self) -> Sequence[PolicyRule]:
        async with self._session_factory() as session:
            rows = await session.scalars(select(PolicyRuleRow).order_by(PolicyRuleRow.priority.asc(), PolicyRuleRow.name.asc()))
            return [
                PolicyRule(
                    id=row.id,
                    name=row.name,
                    description=row.description,
                    effect=row.effect,
                    operation=row.invocation_action,
                    subject=PolicySubject(agent_ids=row.subject_agent_ids),
                    resource=PolicyResource(tool_names=[row.tool]),
                    conditions=[PolicyCondition.model_validate(item) for item in row.conditions],
                    priority=row.priority,
                    enabled=row.enabled,
                )
                for row in rows
            ]

    async def get_policy(self, policy_id: str) -> PolicyRule | None:
        async with self._session_factory() as session:
            row = await session.get(PolicyRuleRow, policy_id)
            if row is None:
                return None
            return PolicyRule(
                id=row.id,
                name=row.name,
                description=row.description,
                effect=row.effect,
                operation=row.invocation_action,
                subject=PolicySubject(agent_ids=row.subject_agent_ids),
                resource=PolicyResource(tool_names=[row.tool]),
                conditions=[PolicyCondition.model_validate(item) for item in row.conditions],
                priority=row.priority,
                enabled=row.enabled,
            )

    async def upsert_policy(self, policy: PolicyRule) -> PolicyRule:
        async with self._session_factory() as session:
            row = PolicyRuleRow(
                id=str(policy.id),
                agent_id=policy.subject.agent_ids[0] if policy.subject.agent_ids else "*",
                name=policy.name,
                description=policy.description,
                effect=policy.effect,
                tool=policy.resource.tool_names[0] if policy.resource.tool_names else "*",
                subject_agent_ids=policy.subject.agent_ids,
                invocation_action=policy.operation,
                conditions=[condition.model_dump(mode="json") for condition in policy.conditions],
                priority=policy.priority,
                enabled=policy.enabled,
            )
            await session.merge(row)
            await session.commit()
        return policy

    async def delete_policy(self, policy_id: str) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(delete(PolicyRuleRow).where(PolicyRuleRow.id == policy_id))
            await session.commit()
            return result.rowcount > 0


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
                    matched_policy_id=entry.matched_policy_id,
                    request_payload=entry.request_payload,
                    created_at=entry.created_at,
                )
            )
            await session.commit()

    async def list_entries(self, query: AuditLogQuery) -> Sequence[AuditLogEntry]:
        async with self._session_factory() as session:
            statement = select(AuditLogRow).order_by(desc(AuditLogRow.created_at)).limit(query.limit)
            if query.agent_id:
                statement = statement.where(AuditLogRow.agent_id == query.agent_id)
            if query.tool_name:
                statement = statement.where(AuditLogRow.tool_name == query.tool_name)
            rows = await session.scalars(statement)
            return [
                AuditLogEntry(
                    id=row.id,
                    agent_id=row.agent_id,
                    tool_name=row.tool_name,
                    decision=row.decision,
                    reason=row.reason,
                    matched_policy_id=row.matched_policy_id,
                    request_payload=row.request_payload,
                    created_at=row.created_at,
                )
                for row in rows
            ]


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
                schema=[ToolArgumentSpec.model_validate(item) for item in row.input_schema],
            )

    async def list_adapters(self) -> Sequence[AdapterConfig]:
        async with self._session_factory() as session:
            rows = await session.scalars(select(AdapterConfigRow).order_by(AdapterConfigRow.tool_name.asc()))
            return [
                AdapterConfig(
                    tool_name=row.tool_name,
                    target_uri=row.target_uri,
                    timeout_seconds=row.timeout_seconds,
                    schema=[ToolArgumentSpec.model_validate(item) for item in row.input_schema],
                )
                for row in rows
            ]

    async def upsert_adapter(self, adapter: AdapterConfig) -> AdapterConfig:
        async with self._session_factory() as session:
            row = AdapterConfigRow(
                tool_name=adapter.tool_name,
                target_uri=adapter.target_uri,
                timeout_seconds=adapter.timeout_seconds,
                input_schema=[spec.model_dump(mode="json") for spec in adapter.input_schema],
            )
            await session.merge(row)
            await session.commit()
        return adapter

    async def delete_adapter(self, tool_name: str) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(delete(AdapterConfigRow).where(AdapterConfigRow.tool_name == tool_name))
            await session.commit()
            return result.rowcount > 0


class PostgresRuntimeConfigRepository(RuntimeConfigRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def get(self, key: str) -> RuntimeConfig | None:
        async with self._session_factory() as session:
            row = await session.get(RuntimeConfigRow, key)
            if row is None:
                return None
            return RuntimeConfig(key=row.key, value=row.value)

    async def list_configs(self) -> Sequence[RuntimeConfig]:
        async with self._session_factory() as session:
            rows = await session.scalars(select(RuntimeConfigRow).order_by(RuntimeConfigRow.key.asc()))
            return [RuntimeConfig(key=row.key, value=row.value) for row in rows]

    async def upsert_config(self, config: RuntimeConfig) -> RuntimeConfig:
        async with self._session_factory() as session:
            await session.merge(RuntimeConfigRow(key=config.key, value=config.value))
            await session.commit()
        return config

    async def delete_config(self, key: str) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(delete(RuntimeConfigRow).where(RuntimeConfigRow.key == key))
            await session.commit()
            return result.rowcount > 0
