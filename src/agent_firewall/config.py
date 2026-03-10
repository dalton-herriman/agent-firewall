from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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


@lru_cache
def get_settings() -> Settings:
    return Settings()

