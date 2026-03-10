from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from agent_firewall.config import Settings


@dataclass(slots=True)
class AuthPrincipal:
    actor_id: str
    tenant_id: str
    scopes: set[str]


def resolve_api_key(settings: Settings, api_key: str | None) -> AuthPrincipal | None:
    if not settings.auth_enabled:
        return AuthPrincipal(actor_id="anonymous", tenant_id="default", scopes={"evaluate", "manage"})
    if not api_key:
        return None
    for entry in settings.api_keys:
        if entry.key == api_key:
            return AuthPrincipal(actor_id=entry.actor_id, tenant_id=entry.tenant_id, scopes=set(entry.scopes))
    return None


def require_scope(request: Request, scope: str) -> AuthPrincipal:
    settings: Settings = request.app.state.settings
    principal = resolve_api_key(settings, request.headers.get("x-agent-firewall-key"))
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing api key")
    if scope not in principal.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient scope")
    return principal
