# ADR 0001: Compose established open-source projects; build only the control plane

Status: accepted (2026-10-09)

## Context

Microsoft Agent 365 combines a registry, an identity provider (Entra Agent ID), access
policies (Conditional Access), a tooling gateway, data protection (Purview) and threat
protection (Defender). Open-source projects already cover most of these individually, are
maintained by larger communities, and are more likely to be trusted by security teams
than new code.

## Decision

Use Keycloak for identity, OPA for policy decisions, agentgateway for MCP enforcement,
Presidio for personal-data detection and the OpenTelemetry Collector for telemetry.
Write only what none of them provides: the agent registry and lifecycle (owners,
sponsors, blueprints, approval, attestation, discovery, risk), the reconcilers that keep
the other components in sync with it, a governance processor for agentgateway's
`ExtMcp` hook, and the evidence ledger.

## Consequences

* The platform inherits the components' hardening, protocol support (for example the
  stateless MCP revision) and release cadence.
* Operators run more processes; the reference deployment is a Docker Compose stack, with
  Kubernetes packaging on the roadmap.
* Version compatibility across components must be tested; the checks validate generated
  agentgateway configuration with the real binary and evaluate the bundle with real OPA.
