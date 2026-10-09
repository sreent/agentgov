# ADR 0002: OPA (Rego) is the single policy decision point

Status: accepted (2026-10-09)

## Context

Agent authorization happens in more than one place: at the gateway for MCP traffic, and
inside agent frameworks for tools that never leave the process. Candidates were OPA,
Cedar and Cerbos. Cedar has momentum in agent products (AWS AgentCore Policy, ToolHive)
and is analyzable, but agentgateway has no native Cedar integration.

## Decision

Use OPA. The control plane builds one bundle (the Rego library, organisation policies and
registry data) and serves it with long polling. The governance processor queries
`data.agentgov.mcp.*`; the Agent Governance Toolkit queries `data.agentos.allow` in
remote mode. Organisation policies are Rego modules in `agentgov.custom.*`, validated
before distribution.

## Consequences

* One policy source, two enforcement points, no glue code at either.
* Rego has a learning curve; the library exposes helpers (`data.agentgov.context`) and the
  docs give patterns. The decision input is shaped close to AuthZEN (subject, action,
  resource, context) to keep a future engine swap feasible.
* A broken bundle would freeze OPA on its last good revision, so organisation policies are
  compiled and smoke-evaluated before acceptance, and OPA status errors raise findings.
