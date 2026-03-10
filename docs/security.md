# Server Security

When `AGENT_FIREWALL_AUTH_ENABLED=true`, requests must include `X-Agent-Firewall-Key`.

`AGENT_FIREWALL_API_KEYS` accepts a JSON array of key definitions. Each entry must set exactly one of `key` or `key_sha256`.

```json
[
  {
    "key_id": "dev-key-2026-03",
    "key_sha256": "<sha256-of-dev-key>",
    "actor_id": "local-admin",
    "tenant_id": "default",
    "roles": ["admin"],
    "scopes": [],
    "project_ids": ["project-a"],
    "status": "active",
    "not_before": null,
    "expires_at": null
  }
]
```

Use `from agent_firewall import hash_api_key` to generate the digest for a plaintext key before putting it into config.

Keys can be staged for rotation by setting:

- `not_before` to delay activation until a cutover time
- `expires_at` to end the validity window
- `status` to `disabled` to revoke a key without removing its config entry

Management and evaluation APIs are tenant-scoped. Control-plane changes are written to the audit log with the authenticated `actor_id`, including publish and rollback operations.

For audit-log reads, project-scoped API keys can only read within their configured projects:

- if the key has one `project_id`, the audit endpoint automatically scopes to that project when no query filter is supplied
- if the key has multiple `project_ids`, callers must provide an explicit `project_id`
- requesting an out-of-scope project returns `403`
