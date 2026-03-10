# Product Positioning

Agent Firewall is an SDK-first project.

The main product is the Python library. The FastAPI server exists to support teams that outgrow in-process deployment and need a centralized control plane.

## Primary path

Start with the SDK when:

- you want the lowest-friction OSS adoption path
- your agent framework already executes tools in-process
- you want policy enforcement without adding a new service dependency
- you want to prove the control model before operationalizing shared infrastructure

## Secondary path

Add `agent-firewall-server` when:

- multiple agents need the same policy and audit plane
- platform teams need centralized policy administration
- you need tenant or project isolation at the service boundary
- you want brokered execution instead of direct tool invocation from the agent process

## What this project is not

- not a general-purpose API gateway for arbitrary microservices
- not an agent framework
- not a replacement for application authorization or infrastructure IAM

## Product boundary

The SDK should remain the easiest way to adopt Agent Firewall.

The server should remain optional and should reuse the same request models, policy semantics, and execution contracts as the library. New capabilities should generally land in the shared engine first, then surface through the server only when centralization adds value.
