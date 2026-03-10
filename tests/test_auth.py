from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agent_firewall.auth import hash_api_key, resolve_api_key
from agent_firewall.config import ApiKeyConfig, Settings


def test_resolve_api_key_supports_sha256_hashed_secrets() -> None:
    settings = Settings(
        app_env="test",
        auth_enabled=True,
        api_keys=[
            ApiKeyConfig(
                key_id="hashed-key",
                key_sha256=hash_api_key("super-secret"),
                actor_id="svc",
                tenant_id="tenant-a",
                roles=["operator"],
            )
        ],
    )

    principal = resolve_api_key(settings, "super-secret")

    assert principal is not None
    assert principal.key_id == "hashed-key"
    assert principal.tenant_id == "tenant-a"


def test_resolve_api_key_rejects_not_yet_active_keys() -> None:
    settings = Settings(
        app_env="test",
        auth_enabled=True,
        api_keys=[
            ApiKeyConfig(
                key_id="future-key",
                key="future-secret",
                actor_id="svc",
                tenant_id="tenant-a",
                roles=["operator"],
                not_before=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        ],
    )

    principal = resolve_api_key(settings, "future-secret")

    assert principal is None


def test_api_key_config_requires_exactly_one_secret_source() -> None:
    with pytest.raises(ValidationError):
        ApiKeyConfig(
            key_id="bad-key",
            key="plaintext",
            key_sha256=hash_api_key("plaintext"),
            actor_id="svc",
            tenant_id="tenant-a",
        )


def test_settings_reject_duplicate_key_ids() -> None:
    with pytest.raises(ValidationError):
        Settings(
            app_env="test",
            auth_enabled=True,
            api_keys=[
                ApiKeyConfig(
                    key_id="dup-key",
                    key="secret-1",
                    actor_id="svc",
                    tenant_id="tenant-a",
                ),
                ApiKeyConfig(
                    key_id="dup-key",
                    key="secret-2",
                    actor_id="svc",
                    tenant_id="tenant-a",
                ),
            ],
        )
