from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator


class ToolSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    input_schema: dict[str, JsonValue] = Field(default_factory=dict)


class ToolInvocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=200)
    tool_name: str = Field(min_length=1, max_length=200)
    tool_args: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def metadata_keys_must_be_strings(cls, value: dict[str, Any]) -> dict[str, Any]:
        for key in value:
            if not isinstance(key, str):
                raise TypeError("metadata keys must be strings")
        return value


class ToolInvocationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    matched_policy_id: str | None = None
    rate_limit_remaining: int | None = None

