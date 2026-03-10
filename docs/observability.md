# Observability

Agent Firewall now emits observability signals at the core engine layer:

- traces for evaluation and execution
- counters for evaluations, denies, rate-limit events, and executions
- structured log events for evaluation decisions, rate limits, and executions

## Signal names

- `agent_firewall.evaluations`
- `agent_firewall.denies`
- `agent_firewall.rate_limits`
- `agent_firewall.executions`

## Attributes

Signals include tenant and tool dimensions. Evaluation signals also record whether the request was allowed and the decision reason.
