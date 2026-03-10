# Execution Reliability

Brokered execution now includes:

- retry with exponential backoff
- idempotency-key passthrough and result reuse
- a simple per-tool circuit breaker

## Inputs

Set `metadata.idempotency_key` on tool invocations to make repeated execute calls replay-safe on the firewall side.

## Settings

- `execution.max_retries`
- `execution.initial_backoff_seconds`
- `execution.circuit_breaker_threshold`
- `execution.circuit_breaker_reset_seconds`
