from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import JSON, Boolean, Integer, String, Text, delete, desc, select
from sqlalchemy.ext.asyncio import AsyncAttrs, AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from agent_firewall.models.audit import AuditLogEntry, AuditLogQuery
from agent_firewall.models.config import AdapterConfig, RuntimeConfig, ToolArgumentSpec
from agent_firewall.models.policy import PolicyCondition, PolicyResource, PolicyRevision, PolicyRule, PolicySubject
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
    tenant_id: Mapped[str] = mapped_column(String(200), index=True, default="default")
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text(), nullable=True)
    effect: Mapped[str] = mapped_column("action", String(10))
    tool: Mapped[str] = mapped_column(String(200), index=True)
    resource_tool_names: Mapped[list[str]] = mapped_column(JSON, default=list)
    subject_agent_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    invocation_action: Mapped[str] = mapped_column("invocation_action", String(50), default="invoke")
    conditions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(20), default="draft")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class PolicyRevisionRow(Base):
    __tablename__ = "policy_revisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_id: Mapped[str] = mapped_column(String(36), index=True)
    tenant_id: Mapped[str] = mapped_column(String(200), index=True, default="default")
    version: Mapped[int] = mapped_column(Integer, default=1)
    change_summary: Mapped[str] = mapped_column(String(300))
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AuditLogRow(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(200), index=True, default="default")
    project_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    agent_id: Mapped[str] = mapped_column(String(200), index=True)
    tool_name: Mapped[str] = mapped_column(String(200), index=True)
    decision: Mapped[str] = mapped_column(String(10))
    reason: Mapped[str] = mapped_column(String(500))
    matched_policy_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    request_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[str] = mapped_column(String(64), index=True)


class AdapterConfigRow(Base):
    __tablename__ = "adapter_configs"

    tenant_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(200), primary_key=True)
    target_uri: Mapped[str] = mapped_column(Text())
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    input_schema: Mapped[list[dict[str, Any]]] = mapped_column("schema", JSON, default=list)


class RuntimeConfigRow(Base):
    __tablename__ = "runtime_configs"

    tenant_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


def create_engine(database_url: str) -> AsyncEngine:
    return create_async_engine(database_url, future=True)


class PostgresPolicyRepository(PolicyRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def list_rules_for_agent(self, tenant_id: str, agent_id: str) -> Sequence[PolicyRule]:
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(PolicyRuleRow).where(
                    PolicyRuleRow.tenant_id == tenant_id,
                    PolicyRuleRow.enabled.is_(True),
                )
            )
            return [
                PolicyRule(
                    id=row.id,
                    tenant_id=row.tenant_id,
                    name=row.name,
                    description=row.description,
                    effect=row.effect,
                    operation=row.invocation_action,
                    subject=PolicySubject(agent_ids=row.subject_agent_ids),
                    resource=PolicyResource(tool_names=row.resource_tool_names or [row.tool]),
                    conditions=[PolicyCondition.model_validate(item) for item in row.conditions],
                    priority=row.priority,
                    version=row.version,
                    status=row.status,
                    enabled=row.enabled,
                )
                for row in rows
                if not row.subject_agent_ids or agent_id in row.subject_agent_ids
            ]

    async def list_policies(self, tenant_id: str) -> Sequence[PolicyRule]:
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(PolicyRuleRow).where(PolicyRuleRow.tenant_id == tenant_id).order_by(PolicyRuleRow.priority.asc(), PolicyRuleRow.name.asc())
            )
            return [
                PolicyRule(
                    id=row.id,
                    tenant_id=row.tenant_id,
                    name=row.name,
                    description=row.description,
                    effect=row.effect,
                    operation=row.invocation_action,
                    subject=PolicySubject(agent_ids=row.subject_agent_ids),
                    resource=PolicyResource(tool_names=row.resource_tool_names or [row.tool]),
                    conditions=[PolicyCondition.model_validate(item) for item in row.conditions],
                    priority=row.priority,
                    version=row.version,
                    status=row.status,
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
                tenant_id=row.tenant_id,
                name=row.name,
                description=row.description,
                effect=row.effect,
                operation=row.invocation_action,
                subject=PolicySubject(agent_ids=row.subject_agent_ids),
                resource=PolicyResource(tool_names=row.resource_tool_names or [row.tool]),
                conditions=[PolicyCondition.model_validate(item) for item in row.conditions],
                priority=row.priority,
                version=row.version,
                status=row.status,
                enabled=row.enabled,
            )

    async def upsert_policy(self, policy: PolicyRule) -> PolicyRule:
        async with self._session_factory() as session:
            row = PolicyRuleRow(
                id=str(policy.id),
                agent_id=policy.subject.agent_ids[0] if policy.subject.agent_ids else "*",
                tenant_id=policy.tenant_id,
                name=policy.name,
                description=policy.description,
                effect=policy.effect,
                tool=policy.resource.tool_names[0] if policy.resource.tool_names else "*",
                resource_tool_names=policy.resource.tool_names,
                subject_agent_ids=policy.subject.agent_ids,
                invocation_action=policy.operation,
                conditions=[condition.model_dump(mode="json") for condition in policy.conditions],
                priority=policy.priority,
                version=policy.version,
                status=policy.status,
                enabled=policy.enabled,
            )
            await session.merge(row)
            await session.commit()
        return policy

    async def delete_policy(self, tenant_id: str, policy_id: str) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(
                delete(PolicyRuleRow).where(PolicyRuleRow.tenant_id == tenant_id, PolicyRuleRow.id == policy_id)
            )
            await session.commit()
            return result.rowcount > 0

    async def list_policy_revisions(self, tenant_id: str, policy_id: str) -> Sequence[PolicyRevision]:
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(PolicyRevisionRow)
                .where(PolicyRevisionRow.tenant_id == tenant_id, PolicyRevisionRow.policy_id == policy_id)
                .order_by(PolicyRevisionRow.version.desc())
            )
            return [
                PolicyRevision(
                    policy_id=row.policy_id,
                    tenant_id=row.tenant_id,
                    version=row.version,
                    snapshot=PolicyRule.model_validate(row.snapshot),
                    change_summary=row.change_summary,
                )
                for row in rows
            ]

    async def append_policy_revision(self, revision: PolicyRevision) -> None:
        async with self._session_factory() as session:
            session.add(
                PolicyRevisionRow(
                    policy_id=str(revision.policy_id),
                    tenant_id=revision.tenant_id,
                    version=revision.version,
                    change_summary=revision.change_summary,
                    snapshot=revision.snapshot.model_dump(mode="json", by_alias=True),
                )
            )
            await session.commit()


class PostgresAuditLogRepository(AuditLogRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def record(self, entry: AuditLogEntry) -> None:
        async with self._session_factory() as session:
            session.add(
                AuditLogRow(
                    id=str(entry.id),
                    tenant_id=entry.tenant_id,
                    project_id=entry.project_id,
                    actor_id=entry.actor_id,
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
            if query.tenant_id:
                statement = statement.where(AuditLogRow.tenant_id == query.tenant_id)
            if query.project_id:
                statement = statement.where(AuditLogRow.project_id == query.project_id)
            if query.agent_id:
                statement = statement.where(AuditLogRow.agent_id == query.agent_id)
            if query.tool_name:
                statement = statement.where(AuditLogRow.tool_name == query.tool_name)
            rows = await session.scalars(statement)
            return [
                AuditLogEntry(
                    id=row.id,
                    tenant_id=row.tenant_id,
                    project_id=row.project_id,
                    actor_id=row.actor_id,
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

    async def get_by_tool_name(self, tenant_id: str, tool_name: str) -> AdapterConfig | None:
        async with self._session_factory() as session:
            row = await session.get(AdapterConfigRow, {"tenant_id": tenant_id, "tool_name": tool_name})
            if row is None:
                return None
            return AdapterConfig(
                tenant_id=row.tenant_id,
                tool_name=row.tool_name,
                target_uri=row.target_uri,
                timeout_seconds=row.timeout_seconds,
                schema=[ToolArgumentSpec.model_validate(item) for item in row.input_schema],
            )

    async def list_adapters(self, tenant_id: str) -> Sequence[AdapterConfig]:
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(AdapterConfigRow).where(AdapterConfigRow.tenant_id == tenant_id).order_by(AdapterConfigRow.tool_name.asc())
            )
            return [
                AdapterConfig(
                    tenant_id=row.tenant_id,
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
                tenant_id=adapter.tenant_id,
                tool_name=adapter.tool_name,
                target_uri=adapter.target_uri,
                timeout_seconds=adapter.timeout_seconds,
                input_schema=[spec.model_dump(mode="json") for spec in adapter.input_schema],
            )
            await session.merge(row)
            await session.commit()
        return adapter

    async def delete_adapter(self, tenant_id: str, tool_name: str) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(
                delete(AdapterConfigRow).where(AdapterConfigRow.tenant_id == tenant_id, AdapterConfigRow.tool_name == tool_name)
            )
            await session.commit()
            return result.rowcount > 0


class PostgresRuntimeConfigRepository(RuntimeConfigRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def get(self, tenant_id: str, key: str) -> RuntimeConfig | None:
        async with self._session_factory() as session:
            row = await session.get(RuntimeConfigRow, {"tenant_id": tenant_id, "key": key})
            if row is None:
                return None
            return RuntimeConfig(tenant_id=row.tenant_id, key=row.key, value=row.value)

    async def list_configs(self, tenant_id: str) -> Sequence[RuntimeConfig]:
        async with self._session_factory() as session:
            rows = await session.scalars(select(RuntimeConfigRow).where(RuntimeConfigRow.tenant_id == tenant_id).order_by(RuntimeConfigRow.key.asc()))
            return [RuntimeConfig(tenant_id=row.tenant_id, key=row.key, value=row.value) for row in rows]

    async def upsert_config(self, config: RuntimeConfig) -> RuntimeConfig:
        async with self._session_factory() as session:
            await session.merge(RuntimeConfigRow(tenant_id=config.tenant_id, key=config.key, value=config.value))
            await session.commit()
        return config

    async def delete_config(self, tenant_id: str, key: str) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(
                delete(RuntimeConfigRow).where(RuntimeConfigRow.tenant_id == tenant_id, RuntimeConfigRow.key == key)
            )
            await session.commit()
            return result.rowcount > 0
