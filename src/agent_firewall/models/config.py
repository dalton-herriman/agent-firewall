from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AdapterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(min_length=1, max_length=200)
    target_uri: str = Field(min_length=1)
    timeout_seconds: int = Field(default=10, ge=1, le=300)
    input_schema: dict[str, Any] = Field(default_factory=dict, alias="schema", serialization_alias="schema")


class RuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=200)
    value: dict[str, Any] = Field(default_factory=dict)
