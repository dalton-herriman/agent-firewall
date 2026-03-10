# Agent Firewall

Agent Firewall is designed as two deliverables built on the same core policy engine.

## Deliverables

- `agent-firewall` Python SDK
  - Library-first adoption path for OSS agent projects
  - Middleware, decorators, and hooks that wrap tool calls before execution
  - Embeddable policy evaluation, audit logging, and rate limiting
- `agent-firewall-server`
  - Optional FastAPI service for teams that want centralized policy management and audit collection
  - Reuses the same core engine underneath the SDK

## Stack

- Pydantic v2 for request, tool-arg, and policy validation
- PostgreSQL for policies, audit logs, adapters, and runtime config
- Redis for caching and rate-limit state
- OpenTelemetry for traces, metrics, and logs integration points
- FastAPI for the optional gateway/API layer

## Quick start

1. Create a local virtual environment with `python3 -m venv .venv`.
2. Activate it with `source .venv/bin/activate`.
3. Install the package in editable mode with the `dev` extras.
4. Start local dependencies with `docker compose up -d postgres redis`.
5. Apply the initial schema with `alembic upgrade head`.
6. Embed `AgentFirewallSDK` in your agent runtime and wrap tool calls with `tool_guard` or `ToolHook`.
7. Optionally run `uvicorn agent_firewall.server:create_server_app --factory --reload` for a centralized service.

For real backing service validation, use `make verify-stack` and `make test-integration` after Postgres and Redis are running.

## Docs

- [Architecture](docs/architecture.md)
- [Adoption paths](docs/adoption.md)
- [Development](docs/development.md)
- [Integrations](docs/integrations.md)
- [Policy semantics](docs/policies.md)
- [Execution boundary](docs/execution.md)
- [Server API](docs/server.md)
