from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_firewall.models.common import new_id


class PolicyCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(min_length=1)
    operator: Literal["eq", "neq", "in", "not_in", "contains", "regex"]
    value: Any


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=new_id)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    action: Literal["allow", "deny"]
    tool: str = Field(min_length=1, max_length=200)
    conditions: list[PolicyCondition] = Field(default_factory=list)
    priority: int = Field(default=100, ge=0)
    enabled: bool = True

    @field_validator("conditions")
    @classmethod
    def require_conditions_for_allow(cls, conditions: list[PolicyCondition]) -> list[PolicyCondition]:
        return conditions


class PolicySet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=200)
    rules: list[PolicyRule] = Field(default_factory=list)

