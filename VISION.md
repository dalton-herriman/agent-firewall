# Agent Firewall

Security Guardrails for AI Agent Tool Use

---

# Vision

AI agents are rapidly evolving from simple chat interfaces into autonomous systems capable of calling tools, querying databases, modifying infrastructure, and executing business workflows.

These agents operate with increasing levels of autonomy, yet the security model around them remains immature.

Today most AI agents can directly call tools or APIs with little to no control layer. This creates a dangerous environment where prompt injection, malicious inputs, or simple model mistakes can lead to data exfiltration, destructive actions, or unauthorized access.

The vision of **Agent Firewall** is to introduce a **security control plane for AI tool usage**.

Just as web applications require firewalls, authentication layers, and request validation, AI agents require a protective boundary around the tools they can access.

Agent Firewall sits between agents and their tools, inspecting every request and enforcing policies before any action is executed.

---

# Mission

Create a lightweight, developer-friendly security layer that ensures AI agents can only perform safe, authorized, and observable actions.

Agent Firewall should:

- Prevent dangerous or unintended tool usage
- Limit the blast radius of prompt injection attacks
- Provide visibility into agent behavior
- Introduce basic policy enforcement for tool calls
- Become the standard middleware for secure AI agents

---

# Core Principles

## Interpose All Tool Calls

Agents should never directly invoke tools.

All tool invocations must pass through the firewall.
