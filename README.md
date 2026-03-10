# Agent Firewall

Agent Firewall is an SDK-first control layer for AI agent tool use.

The primary product is the `agent-firewall` Python library: embed it directly in an agent runtime, wrap tool calls, and enforce policy without introducing a new network hop. `agent-firewall-server` is a secondary deployment option for teams that need centralized policy management, audit collection, or brokered execution.

See [CHANGELOG.md](CHANGELOG.md) for release notes and [CONTRIBUTING.md](CONTRIBUTING.md) for contributor workflow.

## Deliverables

- `agent-firewall` Python SDK
  - Primary product and default adoption path
  - Library-first adoption path for OSS agent projects
  - Middleware, decorators, and hooks that wrap tool calls before execution
  - Embeddable policy evaluation, audit logging, and rate limiting
- `agent-firewall-server`
  - Optional FastAPI control plane built on the same engine
  - Intended for teams that want centralized policy management and audit collection
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

## Positioning

Use the SDK when you want the easiest OSS adoption path, the lowest operational overhead, and an in-process enforcement boundary around tools.

Add the server when you need shared policy storage, shared audit visibility, tenant isolation, or a network execution boundary across multiple agents.

## Docs

- [Architecture](docs/architecture.md)
- [Adoption paths](docs/adoption.md)
- [Development](docs/development.md)
- [Examples](docs/examples.md)
- [Integrations](docs/integrations.md)
- [Policy semantics](docs/policies.md)
- [Policy workflow](docs/policy-workflow.md)
- [Product positioning](docs/positioning.md)
- [Execution reliability](docs/reliability.md)
- [Execution boundary](docs/execution.md)
- [Server security](docs/security.md)
- [Authorization](docs/authorization.md)
- [Observability](docs/observability.md)
- [Server API](docs/server.md)
