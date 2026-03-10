# Adoption Paths

The recommended path is to start with the SDK and only introduce the server when you need centralization.

## OSS-first

Embed the SDK directly in the agent process.

```python
from agent_firewall import AgentFirewallSDK, GuardedTool, guard_langchain_tool, guard_openai_tool
```

Use this path when:

- you want the smallest integration surface
- your agent already runs tool calls in-process
- you do not need centralized policy management yet
- you want the default OSS adoption path for this project

## Centralized team deployment

Run `agent-firewall-server` and route tool requests through FastAPI.

Use this path when:

- multiple agents need a shared policy plane
- you need centralized audit logs
- you want a clear network boundary between agents and tool execution

## Migration path

Start with the SDK.

When requirements expand, keep the same engine contracts and move policy and audit storage to the server deployment. The current scaffold is intended to preserve that migration path instead of forcing a rewrite.
