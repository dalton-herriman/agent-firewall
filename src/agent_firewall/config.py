from datetime import datetime
from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiKeyConfig(BaseModel):
    key_id: str = Field(min_length=1, max_length=200)
    key: str | None = None
    key_sha256: str | None = None
    actor_id: str
    tenant_id: str
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)
    project_ids: list[str] = Field(default_factory=list)
    status: Literal["active", "disabled"] = "active"
    not_before: datetime | None = None
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_secret_source(self) -> "ApiKeyConfig":
        if bool(self.key) == bool(self.key_sha256):
            raise ValueError("exactly one of key or key_sha256 must be set")
        return self


class ExecutionConfig(BaseModel):
    max_retries: int = 2
    initial_backoff_seconds: float = 0.1
    circuit_breaker_threshold: int = 3
    circuit_breaker_reset_seconds: int = 30


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENT_FIREWALL_",
        env_file=".env",
        env_nested_delimiter="__",
        extra="ignore",
    )

    app_name: str = "agent-firewall"
    app_env: str = "development"
    app_version: str = "0.1.0"

    api_prefix: str = "/v1"
    database_url: str = Field(
        default="postgresql+asyncpg://agent_firewall:agent_firewall@localhost:5432/agent_firewall"
    )
    redis_url: str = Field(default="redis://localhost:6379/0")
    otel_service_name: str = "agent-firewall"
    otel_exporter_otlp_endpoint: str | None = None
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 30
    default_policy_mode: str = "deny"
    server_broker_enabled: bool = True
    auth_enabled: bool = False
    api_keys: list[ApiKeyConfig] = Field(default_factory=list)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)

    @model_validator(mode="after")
    def validate_api_key_ids(self) -> "Settings":
        seen: set[str] = set()
        for key in self.api_keys:
            if key.key_id in seen:
                raise ValueError(f"duplicate api key id: {key.key_id}")
            seen.add(key.key_id)
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
