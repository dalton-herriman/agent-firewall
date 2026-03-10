# Authorization

API keys now support:

- `key_id`
- `roles`
- `project_ids`
- `status`
- `expires_at`

## Built-in roles

- `admin`: evaluate, manage, audit read
- `operator`: evaluate and manage
- `observer`: audit read only

Revoked or expired keys are rejected. If a key has `project_ids`, evaluation and execution requests must target one of those projects.
