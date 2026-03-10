# Architecture

Agent Firewall is split into a reusable SDK and an optional centralized server.

## Core engine

The shared engine lives in the library package and owns:

- request validation
- policy evaluation
- adapter existence checks
- rate limiting
- audit logging

The main execution path is:

1. Accept a `ToolInvocationRequest`
2. Validate the request shape with Pydantic v2
3. Resolve the target tool adapter
4. Apply Redis-backed rate limiting
5. Evaluate matching policy rules
6. Persist an audit record
7. Return an allow or deny decision

## SDK surface

The SDK is the OSS adoption path. It exposes:

- `AgentFirewallSDK` for direct embedding in agent runtimes
- `GuardedTool` for wrapping callables as protected tools
- `tool_guard` for async decorator-based integration
- `sdk_hook` for framework adapters that want a hook-style primitive

This keeps initial adoption simple: developers can add the library around existing tool functions before they deploy a centralized service.

## Server surface

The FastAPI server is optional. It uses the same engine and provides:

- `GET /health`
- `POST /v1/tool-invocations/evaluate`
- CRUD APIs for policies, adapters, and runtime config
- audit log query APIs

The server is the path for teams that want shared policy storage, centralized logging, and a network boundary between agents and tools.

## Persistence and state

- PostgreSQL repositories back policy rules, audit logs, adapter configs, and runtime config
- Redis holds cache and rate-limit state
- OpenTelemetry instrumentation is configured at app startup for traces and metrics

## Policy semantics

Policies are evaluated against:

- `subject`: the agent identity invoking the tool
- `resource`: tool name patterns
- `action`: currently `invoke`
- `conditions`: request field predicates over tool args and metadata

Rules are sorted by ascending priority. The first matching rule decides the outcome. If nothing matches, the configured default mode applies.
