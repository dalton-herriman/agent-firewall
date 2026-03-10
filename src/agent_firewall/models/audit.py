from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agent_firewall.models.common import new_id, utcnow


class AuditLogEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=new_id)
    tenant_id: str = Field(default="default", min_length=1, max_length=200)
    project_id: str | None = Field(default=None, min_length=1, max_length=200)
    actor_id: str | None = None
    agent_id: str = Field(min_length=1, max_length=200)
    tool_name: str = Field(min_length=1, max_length=200)
    decision: Literal["allow", "deny"]
    reason: str = Field(min_length=1, max_length=500)
    matched_policy_id: str | None = None
    request_payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())


class AuditLogQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str | None = None
    project_id: str | None = None
    agent_id: str | None = None
    tool_name: str | None = None
    limit: int = Field(default=100, ge=1, le=500)
