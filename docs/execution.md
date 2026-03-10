# Execution Boundary

`agent-firewall-server` can now operate in two modes:

- evaluation mode: return allow or deny decisions
- broker mode: evaluate, then dispatch the tool call to the configured adapter target

The broker path is exposed at `POST /v1/tool-invocations/execute`.

## Current broker behavior

- evaluate request through the same core engine
- reject denied or unknown tools before any downstream call
- POST the tool payload to the adapter `target_uri`
- return the downstream JSON payload as the execution result

Disable broker mode with `AGENT_FIREWALL_SERVER_BROKER_ENABLED=false`.
