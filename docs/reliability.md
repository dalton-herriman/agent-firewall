# Execution Reliability

Brokered execution now includes:

- retry with exponential backoff
- idempotency-key passthrough and result reuse
- a simple per-tool circuit breaker

## Inputs

Set `metadata.idempotency_key` on tool invocations to make repeated execute calls replay-safe on the firewall side.

Idempotency reuse is scoped by tenant, project, and tool name so identical client keys do not collide across environments or tools.

## Settings

- `execution.max_retries`
- `execution.initial_backoff_seconds`
- `execution.circuit_breaker_threshold`
- `execution.circuit_breaker_reset_seconds`

The in-memory rate limiter now follows the same windowed reset model as the Redis-backed limiter, which keeps SDK-first local behavior aligned with server deployments.
