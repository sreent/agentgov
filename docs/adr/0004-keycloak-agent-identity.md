# ADR 0004: One Keycloak client per agent

Status: accepted (2026-10-09)

## Context

Entra Agent ID gives every agent its own identity derived from a blueprint, with sponsors
and lifecycle. Shared API keys make attribution and revocation impossible (the IETF WIMSE
agent draft calls static keys an anti-pattern).

## Decision

When an agent is first approved, the control plane creates a confidential client
`agent-<name>` in the AgentGov realm with a service account (client-credentials grant), an
`agent_id` claim and the gateway audience, and a 5-minute token lifetime. Blocking or
deleting the agent disables the client. Credentials are handed to administrators once and
can be rotated. The reconciler is level-triggered and tolerant of concurrent creation.

## Consequences

* Every call through the gateway is attributable to one agent; the processor resolves
  agents from verified claims, never from headers.
* Disabling a client stops new tokens; already-issued tokens are neutralised because OPA
  evaluates the live agent status on every call.
* Secretless authentication (Keycloak federated client authentication with Kubernetes or
  SPIFFE tokens) and on-behalf-of flows (RFC 8693) are the next steps.
