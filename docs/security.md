# Server Security

When `AGENT_FIREWALL_AUTH_ENABLED=true`, requests must include `X-Agent-Firewall-Key`.

`AGENT_FIREWALL_API_KEYS` accepts a JSON array of key definitions:

```json
[
  {
    "key_id": "dev-key-2026-03",
    "key": "dev-key",
    "actor_id": "local-admin",
    "tenant_id": "default",
    "roles": ["admin"],
    "scopes": [],
    "project_ids": ["project-a"],
    "status": "active",
    "expires_at": null
  }
]
```

Management and evaluation APIs are tenant-scoped. Control-plane changes are written to the audit log with the authenticated `actor_id`.
