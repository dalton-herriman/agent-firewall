# Integrations

Agent Firewall is intended to be embedded before a team adopts the centralized server.

## LangChain-style tools

Use `guard_langchain_tool` when your tool surface is already an async callable that receives keyword arguments.

```python
from agent_firewall import AgentFirewallSDK, guard_langchain_tool
```

## OpenAI Agents-style tools

Use `guard_openai_tool` for the same guard pattern around async tool callables in OpenAI-style agent runtimes.

```python
from agent_firewall import AgentFirewallSDK, guard_openai_tool
```

## Generic wrappers

- `GuardedTool` wraps a callable directly
- `tool_guard` gives decorator-style protection
- `sdk_hook` exposes a low-level authorize-only primitive for custom framework adapters
