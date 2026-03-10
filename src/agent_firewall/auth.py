from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status

from agent_firewall.config import Settings


@dataclass(slots=True)
class AuthPrincipal:
    key_id: str
    actor_id: str
    tenant_id: str
    roles: set[str]
    scopes: set[str]
    project_ids: set[str]


ROLE_SCOPES = {
    "admin": {"evaluate", "manage", "audit:read"},
    "operator": {"evaluate", "manage"},
    "observer": {"audit:read"},
}


def resolve_api_key(settings: Settings, api_key: str | None) -> AuthPrincipal | None:
    if not settings.auth_enabled:
        return AuthPrincipal(
            key_id="anonymous",
            actor_id="anonymous",
            tenant_id="default",
            roles={"admin"},
            scopes={"evaluate", "manage", "audit:read"},
            project_ids=set(),
        )
    if not api_key:
        return None
    for entry in settings.api_keys:
        if entry.key == api_key:
            if entry.status != "active":
                return None
            if entry.expires_at and entry.expires_at <= datetime.now(timezone.utc):
                return None
            scopes = set(entry.scopes)
            for role in entry.roles:
                scopes.update(ROLE_SCOPES.get(role, set()))
            return AuthPrincipal(
                key_id=entry.key_id,
                actor_id=entry.actor_id,
                tenant_id=entry.tenant_id,
                roles=set(entry.roles),
                scopes=scopes,
                project_ids=set(entry.project_ids),
            )
    return None


def require_scope(request: Request, scope: str) -> AuthPrincipal:
    settings: Settings = request.app.state.settings
    principal = resolve_api_key(settings, request.headers.get("x-agent-firewall-key"))
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing api key")
    if scope not in principal.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient scope")
    return principal
