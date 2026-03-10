# Server API

The optional FastAPI service exposes the shared policy engine over HTTP.

## Evaluation

- `POST /v1/tool-invocations/evaluate`
- `POST /v1/tool-invocations/execute`

## Policy management

- `GET /v1/policies`
- `POST /v1/policies`
- `POST /v1/policies/validate`
- `GET /v1/policies/{policy_id}`
- `PUT /v1/policies/{policy_id}`
- `DELETE /v1/policies/{policy_id}`

## Adapter management

- `GET /v1/adapters`
- `POST /v1/adapters`
- `GET /v1/adapters/{tool_name}`
- `PUT /v1/adapters/{tool_name}`
- `DELETE /v1/adapters/{tool_name}`

## Runtime config management

- `GET /v1/runtime-config`
- `POST /v1/runtime-config`
- `GET /v1/runtime-config/{key}`
- `PUT /v1/runtime-config/{key}`
- `DELETE /v1/runtime-config/{key}`

## Audit logs

- `GET /v1/audit-logs`
  - supports `agent_id`, `tool_name`, and `limit` query parameters
