# Roadmap

AgentGov is alpha software. The reference stack covers the core of the Agent 365 baseline
(see the [parity matrix](baseline-agent365.md)); the items below close the remaining gaps.
They follow the same rule as everything else: use an established project when one exists
and write only the glue.

## Next

| Theme | Item | Building block |
|---|---|---|
| Identity | **On-behalf-of flows**: agents acting for a signed-in user, with the user and the agent both visible to policy (`act` claim) | Keycloak token exchange (RFC 8693) |
| Identity | **Secretless agent credentials**: workloads authenticate with platform-issued tokens instead of client secrets | Keycloak federated client authentication (Kubernetes service account tokens, SPIFFE) |
| Identity | **Incremental identity reconciliation**: a change notification per agent instead of a periodic full sync | — |
| Deployment | **Kubernetes packaging**: Helm chart for the control plane and processor, agentgateway via its Kubernetes controller, OPA as a sidecar or deployment | Helm, agentgateway |
| Deployment | **Multi-replica control plane**: fan out bundle and config change notifications across replicas | PostgreSQL `LISTEN` / `NOTIFY` |
| Admin access | **Back-channel logout**: end administrator sessions as soon as the identity provider ends them, instead of at expiry | OpenID Connect Back-Channel Logout (supported by Keycloak) |
| Security | **Mutual TLS between components**: the gateway, processor, OPA and control plane authenticate each other instead of relying on network isolation | SPIFFE / SPIRE or cert-manager certificates |
| Detection | **Prompt-injection classifier**: an optional model-based detector next to the heuristics | An open classifier model served behind a small HTTP API |
| Security operations | **SIEM integration**: stream ledger entries and findings in a standard schema | OCSF, OpenTelemetry logs |

## Later

| Theme | Item | Building block |
|---|---|---|
| Registry | **Management rules**: declarative registry rules (for example "block agents without an owner for 14 days") on top of posture findings | OPA |
| Registry | **More platform connectors**: import agents from cloud agent platforms and SaaS agent builders (AWS, Google, Salesforce, Databricks) the way [Microsoft 365 and Copilot Studio](platforms.md) are | Platform APIs |
| Registry | **Block platform agents from AgentGov**, once Microsoft's block API accepts an application rather than only a signed-in administrator | Microsoft Graph |
| Access | **Access packages**: time-bound, requestable bundles of tool grants with approval | — |
| Interoperability | **A2A governance**: agent-to-agent calls through the gateway with the same identity and policy | agentgateway A2A routes |
| Policy | **AuthZEN interface** so the decision point can be swapped (for example to Cedar) without touching enforcement points | OpenID AuthZEN |
| Evidence | **External anchoring** of ledger checkpoints, and signed OPA bundles | Sigstore, OPA bundle signing |
| Evidence | **Retention policies** for activity, decisions and ledger exports | — |

## Out of scope

* **Distributing agents to end users** (an agent store). AgentGov governs agents; it is
  not a marketplace.
* **Microsoft 365-specific tooling** such as the Work IQ MCP servers. Any MCP server can be
  registered and governed.
* **Sandboxing agent code.** AgentGov controls what agents may do through the tools they
  call; isolating the agent process itself is the job of the runtime (containers, gVisor,
  microVMs, or the Agent Governance Toolkit's execution rings).

Proposals are welcome: open an issue describing the problem and the established project
you would build it on.
