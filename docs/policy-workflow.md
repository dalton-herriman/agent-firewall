# Policy Workflow

Policies now support stateful authoring:

- `draft`
- `published`
- `archived`

Each write stores a revision snapshot. The server adds:

- `GET /v1/policies/{policy_id}/revisions`
- `POST /v1/policies/{policy_id}/publish`
- `POST /v1/policies/{policy_id}/rollback/{version}`
