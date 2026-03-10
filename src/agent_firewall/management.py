from __future__ import annotations

from collections.abc import Sequence

from agent_firewall.models.audit import AuditLogEntry, AuditLogQuery
from agent_firewall.models.config import AdapterConfig, RuntimeConfig
from agent_firewall.models.policy import PolicyRevision, PolicyRule, PolicyValidationResult
from agent_firewall.policy import validate_policy_candidate
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

    async def list_policies(self, tenant_id: str) -> Sequence[PolicyRule]:
        return await self._policy_repository.list_policies(tenant_id)

    async def get_policy(self, policy_id: str) -> PolicyRule | None:
        return await self._policy_repository.get_policy(policy_id)

    async def upsert_policy(self, policy: PolicyRule) -> PolicyRule:
        validation = await self.validate_policy(policy)
        if not validation.valid:
            raise ValueError("; ".join(validation.errors))
        stored = await self._policy_repository.upsert_policy(policy)
        await self._policy_repository.append_policy_revision(
            PolicyRevision(
                policy_id=stored.id,
                tenant_id=stored.tenant_id,
                version=stored.version,
                snapshot=stored,
                change_summary=f"policy {stored.status}",
            )
        )
        return stored

    async def validate_policy(self, policy: PolicyRule) -> PolicyValidationResult:
        existing = await self._policy_repository.list_policies(policy.tenant_id)
        return validate_policy_candidate(policy, existing)

    async def delete_policy(self, tenant_id: str, policy_id: str) -> bool:
        return await self._policy_repository.delete_policy(tenant_id, policy_id)

    async def list_policy_revisions(self, tenant_id: str, policy_id: str) -> Sequence[PolicyRevision]:
        return await self._policy_repository.list_policy_revisions(tenant_id, policy_id)

    async def publish_policy(self, tenant_id: str, policy_id: str) -> PolicyRule | None:
        policy = await self.get_policy(policy_id)
        if policy is None or policy.tenant_id != tenant_id:
            return None
        return await self.upsert_policy(policy.model_copy(update={"status": "published", "version": policy.version + 1}))

    async def rollback_policy(self, tenant_id: str, policy_id: str, version: int) -> PolicyRule | None:
        revisions = await self.list_policy_revisions(tenant_id, policy_id)
        latest_version = revisions[0].version if revisions else version
        for revision in revisions:
            if revision.version == version:
                restored = revision.snapshot.model_copy(update={"status": "draft", "version": latest_version + 1})
                return await self.upsert_policy(restored)
        return None

    async def list_adapters(self, tenant_id: str) -> Sequence[AdapterConfig]:
        return await self._adapter_repository.list_adapters(tenant_id)

    async def get_adapter(self, tenant_id: str, tool_name: str) -> AdapterConfig | None:
        return await self._adapter_repository.get_by_tool_name(tenant_id, tool_name)

    async def upsert_adapter(self, adapter: AdapterConfig) -> AdapterConfig:
        return await self._adapter_repository.upsert_adapter(adapter)

    async def delete_adapter(self, tenant_id: str, tool_name: str) -> bool:
        return await self._adapter_repository.delete_adapter(tenant_id, tool_name)

    async def list_configs(self, tenant_id: str) -> Sequence[RuntimeConfig]:
        return await self._runtime_config_repository.list_configs(tenant_id)

    async def get_config(self, tenant_id: str, key: str) -> RuntimeConfig | None:
        return await self._runtime_config_repository.get(tenant_id, key)

    async def upsert_config(self, config: RuntimeConfig) -> RuntimeConfig:
        return await self._runtime_config_repository.upsert_config(config)

    async def delete_config(self, tenant_id: str, key: str) -> bool:
        return await self._runtime_config_repository.delete_config(tenant_id, key)

    async def list_audit_logs(self, query: AuditLogQuery) -> Sequence[AuditLogEntry]:
        return await self._audit_log_repository.list_entries(query)

    async def record_management_event(self, *, tenant_id: str, actor_id: str, action: str, payload: dict) -> None:
        await self._audit_log_repository.record(
            AuditLogEntry(
                tenant_id=tenant_id,
                actor_id=actor_id,
                agent_id=actor_id,
                tool_name="control-plane",
                decision="allow",
                reason=action,
                request_payload=payload,
            )
        )
