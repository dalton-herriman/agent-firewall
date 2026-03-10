from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolArgumentSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    value_type: Literal["string", "integer", "number", "boolean", "object", "array"]
    required: bool = False
    description: str | None = None
    allowed_values: list[Any] = Field(default_factory=list)


class AdapterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    tenant_id: str = Field(default="default", min_length=1, max_length=200)
    tool_name: str = Field(min_length=1, max_length=200)
    target_uri: str = Field(min_length=1)
    timeout_seconds: int = Field(default=10, ge=1, le=300)
    input_schema: list[ToolArgumentSpec] = Field(default_factory=list, alias="schema", serialization_alias="schema")


class RuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(default="default", min_length=1, max_length=200)
    key: str = Field(min_length=1, max_length=200)
    value: dict[str, Any] = Field(default_factory=dict)
