from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agent_firewall.models.common import new_id, utcnow


class AuditLogEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=new_id)
    agent_id: str = Field(min_length=1, max_length=200)
    tool_name: str = Field(min_length=1, max_length=200)
    decision: Literal["allow", "deny"]
    reason: str = Field(min_length=1, max_length=500)
    request_payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())

