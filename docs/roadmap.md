# Roadmap

AgentGov is alpha software. The reference stack covers the core of the Agent 365 baseline
(see the [parity matrix](baseline-agent365.md)). The items below follow the same rule as
everything else: use an established project when one exists and write only the glue.

## Direction

AgentGov grows by governing the points where an agent's actions are authorized, through
the standard interfaces the ecosystem has settled on: tool calls (MCP), model calls,
developers' MCP clients, access on a user's behalf, and calls between agents. One
integration per point covers every vendor that speaks the standard, and each one reuses
the same identities, policies, registry and ledger. Inventories of more agent platforms
come second: they report, but they don't enforce.

## Next, in this order

| | Theme | Item | Building block |
|---|---|---|---|
| 0 | Deployment | **Upgradeable and deployable**: database migrations and a [Helm chart](../deploy/helm/agentgov/README.md) (done) | Alembic, Helm |
| 1 | Model calls | **Govern agents' calls to models**: provider keys held by the gateway, the models each blueprint allows, personal data and secrets masked before prompts leave, jailbreak and injection checks, token budgets, spend per agent and sponsor, and callers the gateway doesn't know discovered as shadow agents | agentgateway's LLM routes and guardrail webhook |
| 2 | Developer tools | **An enterprise MCP registry**: the approved tool servers in the MCP registry format, for GitHub Copilot and VS Code in "registry only" mode, and discovery of the MCP servers configured on developer machines | MCP Registry API |
| 3 | Identity | **Who the agent acts for**: user-delegated tokens at the gateway, the user and their groups in policy, the user in the ledger, approvals sent to the user | Keycloak token exchange (RFC 8693), MCP enterprise-managed authorization (ID-JAG) |
| 4 | Identity | **Bring your own agent identity**: agent tokens from Microsoft Entra Agent ID, Okta, AWS or Kubernetes and SPIFFE workload identity, mapped to registry agents; no client secrets | OIDC federation, Kubernetes service account tokens, SPIFFE |
| 5 | Security operations | **Hand-off at the level you choose**: ledger entries and findings to a SIEM in a standard schema, alerts and approvals in Teams or Slack, and how much the security team's tools may decide | OCSF, OpenTelemetry logs |
| 6 | Interoperability | **Agent-to-agent (A2A) governance**: calls between agents through the gateway, with the chain of delegation in policy and the ledger | agentgateway A2A routes |

## Later

| Theme | Item | Building block |
|---|---|---|
| Deployment | **Multi-replica control plane**: fan out bundle and config change notifications across replicas | PostgreSQL `LISTEN` / `NOTIFY` |
| Security | **Mutual TLS between components**: the gateway, processor, OPA and control plane authenticate each other instead of relying on network isolation | SPIFFE / SPIRE or cert-manager certificates |
| Admin access | **Back-channel logout**: end administrator sessions as soon as the identity provider ends them, instead of at expiry | OpenID Connect Back-Channel Logout (supported by Keycloak) |
| Identity | **Incremental identity reconciliation**: a change notification per agent instead of a periodic full sync | — |
| Detection | **Classifier for tool traffic**: ask the Granite Guardian that already checks [agent instructions](instructions.md) about tool results too (prompt injection), next to the processor's heuristics | IBM Granite Guardian |
| Registry | **Management rules**: declarative registry rules (for example "block agents without an owner for 14 days") on top of posture findings | OPA |
| Registry | **More platform connectors**: import agents from cloud agent platforms and SaaS agent builders (AWS, Google, Salesforce, Databricks) the way [Microsoft 365 and Copilot Studio](platforms.md) are, when someone needs one | Platform APIs |
| Registry | **Block platform agents from AgentGov**, once Microsoft's block API accepts an application rather than only a signed-in administrator | Microsoft Graph |
| Access | **Access packages**: time-bound, requestable bundles of tool grants with approval | — |
| Policy | **AuthZEN interface** so the decision point can be swapped (for example to Cedar) without touching enforcement points | OpenID AuthZEN |
| Evidence | **External anchoring** of ledger checkpoints, and signed OPA bundles | Sigstore, OPA bundle signing |
| Evidence | **Retention policies** for activity, decisions and ledger exports | — |
| Evidence | **Compliance reports** that map the registry and the ledger to the EU AI Act, ISO/IEC 42001 and the NIST AI RMF | — |

## Out of scope

* **Distributing agents to end users** (an agent store). AgentGov governs agents; it is
  not a marketplace.
* **Microsoft 365-specific tooling** such as the Work IQ MCP servers. Any MCP server can be
  registered and governed.
* **Sandboxing agent code.** AgentGov controls what agents may do through the tools they
  call; isolating the agent process itself is the job of the runtime (containers, gVisor,
  microVMs, or the Agent Governance Toolkit's execution rings).
* **Detection models of our own.** AgentGov calls established detectors (Presidio, IBM
  Granite Guardian, and the guardrails agentgateway supports) instead of training its own.

Proposals are welcome: open an issue describing the problem and the established project
you would build it on.
