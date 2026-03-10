from functools import lru_cache

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiKeyConfig(BaseModel):
    key: str
    actor_id: str
    tenant_id: str
    scopes: list[str] = Field(default_factory=list)


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


@lru_cache
def get_settings() -> Settings:
    return Settings()
