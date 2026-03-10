from __future__ import annotations

from fnmatch import fnmatch
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_firewall.models.common import new_id


class PolicyCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(min_length=1)
    operator: Literal["eq", "neq", "in", "not_in", "contains", "regex"]
    value: Any


class PolicySubject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_ids: list[str] = Field(default_factory=list)

    def matches(self, agent_id: str) -> bool:
        return not self.agent_ids or agent_id in self.agent_ids


class PolicyResource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_names: list[str] = Field(default_factory=list)

    def matches(self, tool_name: str) -> bool:
        return not self.tool_names or any(fnmatch(tool_name, pattern) for pattern in self.tool_names)


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: UUID = Field(default_factory=new_id)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    effect: Literal["allow", "deny"] = Field(alias="action", serialization_alias="action")
    operation: Literal["invoke"] = "invoke"
    subject: PolicySubject = Field(default_factory=PolicySubject)
    resource: PolicyResource
    conditions: list[PolicyCondition] = Field(default_factory=list)
    priority: int = Field(default=100, ge=0)
    enabled: bool = True

    @model_validator(mode="before")
    @classmethod
    def upgrade_legacy_shape(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        upgraded = dict(value)
        if "tool" in upgraded and "resource" not in upgraded:
            upgraded["resource"] = {"tool_names": [upgraded.pop("tool")]}
        if "action" in upgraded and upgraded["action"] in {"allow", "deny"} and "effect" not in upgraded:
            upgraded["effect"] = upgraded.pop("action")
        return upgraded


class PolicySet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=200)
    rules: list[PolicyRule] = Field(default_factory=list)
