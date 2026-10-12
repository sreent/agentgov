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

## Delivered, in this order

| | Theme | Item | Building block |
|---|---|---|---|
| 0 | Deployment | **Upgradeable and deployable**: database migrations and a [Helm chart](deploy/kubernetes.md) (done) | Alembic, Helm |
| | Administration | **Choose the features you use** (done): each one on or off, and the controls at the gateway in monitor mode to try them before enforcing them ([features](features.md)). Every item below arrives as a feature | — |
| 1 | Model calls | **Govern agents' calls to models** (done, [model calls](models.md)): provider keys held by the gateway, the models each blueprint allows, personal data masked and credentials refused before prompts leave, jailbreak and injection checks, token budgets, spend per agent, owner and sponsor, and callers the gateway doesn't know discovered as shadow agents | agentgateway's LLM routes and guardrail webhook |
| 2 | Developer tools | **An enterprise MCP registry** (done, [developer tools](developer-tools.md)): the approved tool servers in the MCP registry format, for GitHub Copilot and VS Code in "registry only" mode, and as a managed-settings allowlist; discovery of the MCP servers configured on developer machines | MCP Registry API |
| 3 | Identity | **Who the agent acts for** (done, [acting for people](acting-for-people.md)): tokens agents get for people at the gateway, whom each blueprint's agents may act for, the person and their groups in policy, the person in the ledger, and approvals sent to the person | Keycloak token exchange (RFC 8693) |
| 4 | Identity | **Bring your own agent identity** (done, [agents' own identities](agent-identity.md)): agents authenticate with the identity they already have, Kubernetes service account tokens, SPIFFE JWT-SVIDs, or tokens from Microsoft Entra Agent ID, Okta, AWS and other OpenID Connect issuers, mapped to registry agents; no client secrets, and a kill switch per issuer | Keycloak federated client authentication (Kubernetes, SPIFFE and OpenID Connect identity providers) |
| 5 | Security operations | **Hand-off at the level you choose** (done, [security operations](secops.md)): the ledger, findings included, to SIEMs as OCSF events through OpenTelemetry, an HTTP input or Splunk; alerts, approval requests and kill switches in Teams and Slack; and a `secops` role whose tools may triage, contain or decide as far as you let them | OCSF, OpenTelemetry logs, Splunk HEC, Teams workflows, Slack webhooks |
| 6 | Interoperability | **Agent-to-agent (A2A) governance** (done, [agent to agent](agent-to-agent.md)): calls between agents through the gateway, who may call whom on blueprints and agents, the controls of tool calls on each call, and the chain of agents that handed the work down, with the person at its head, in policy and the ledger of every call further down | agentgateway A2A routes and external authorization |
| 7 | Lifecycle | **Access packages, and issues to the people responsible** (done, [access packages](access-packages.md), [issues](issues.md)): tools, models and agents held for a while once approved, with reminders, renewals, reviews and expiry at the gateway; Microsoft Entra's access packages for agents' identities, read or managed; and findings sent to each agent's owner, sponsors and team, by email and in their chats, escalating until someone acknowledges them | OPA, Microsoft Graph entitlement management, SMTP, Teams workflows, Slack webhooks |
| 8 | Lifecycle | **Management rules** (done, [management rules](management-rules.md)): what to do about agents that meet some conditions for long enough (no activity, no owner, an attestation long overdue, an open finding, a risk level, a status): raise an issue, give them an owner, block, delete or revoke their access packages, after telling their people, monitored before they are enforced, and on a few agents at once at most | — |
| 9 | Evidence | **Retention and compliance evidence** (done, [evidence](evidence.md)): daily checkpoints of the ledger time-stamped by an authority, retention of at least six months with archives that verify offline, operational records kept for a period you choose, and reports for the EU AI Act, ISO/IEC 42001 and the NIST AI RMF with an evidence pack for assessors | RFC 3161 time-stamping authorities, OpenSSL |
| 10 | Deployment | **Production hardening** (done, [production](production.md)): several control-plane replicas on PostgreSQL, with changes reaching every replica at once (a block still stops an agent within a second) and the scheduled work on one leader; decisions that take turns, and edits that can't undo a newer one; mutual TLS between the components; and policy bundles OPA verifies before it uses them. The tests run on PostgreSQL too | PostgreSQL `LISTEN`/`NOTIFY` and advisory locks, OPA bundle signing, cert-manager |
| 11 | Detection | **Deeper detection** (done, [detection](detection.md)): IBM Granite Guardian's second opinion, next to the processor's rules, on tool results, on people's prompts to models and on the answers agents send each other, waited for where it is enforced and given in the background otherwise; and agents' answers to other agents checked as they stream back, with credentials and personal data masked and instructions aimed at the agent that asked withheld | IBM Granite Guardian, agentgateway's external processing |
| 12 | Interoperability | **Masking in calls between agents** (done, [agent to agent](agent-to-agent.md#messages)): personal data in the messages agents send each other masked unless the agent called may have it, monitored before it is enforced | agentgateway's external processing |
| 13 | Interoperability | **Calls around the gateway** (done, [agent to agent](agent-to-agent.md#calls-around-the-gateway)): what AgentGov can't stop, found and told to the agents' owners. Each agent's owners say what stops calls straight to its A2A URL; telemetry shows such calls, and an optional test calls each agent itself. Agents can refuse such calls themselves: the delegation the gateway gives with each call is signed with a key AgentGov publishes, checked with a few lines of Python or any JWT library; and a NetworkPolicy example lets only the gateway reach an agent | JSON Web Key Sets, Kubernetes NetworkPolicy |
| 14 | Evidence | **Ledger checkpoints in a transparency log** (done, [evidence](evidence.md#a-transparency-log)): each checkpoint signed with AgentGov's key and added to Sigstore's public Rekor or a log of your own, its proof checked with the log's key and kept, and handed to assessors as Sigstore bundles that verify offline with cosign | Sigstore Rekor v2 (rekor-tiles) |

## Later

| Theme | Item | Building block |
|---|---|---|
| Security | **Workload identities for the components**: certificates from SPIFFE / SPIRE rather than AgentGov's own authority, rotated automatically | SPIFFE / SPIRE (agentgateway takes SVIDs for its backend TLS) |
| Admin access | **Back-channel logout**: end administrator sessions as soon as the identity provider ends them, instead of at expiry | OpenID Connect Back-Channel Logout (supported by Keycloak) |
| Identity | **Incremental identity reconciliation**: a change notification per agent instead of a periodic full sync | — |
| Identity | **Enterprise-managed authorization for MCP**: accept and issue identity assertions (ID-JAG) for MCP servers outside the gateway, and let developers' MCP clients through the gateway with their own tokens | MCP enterprise-managed authorization, agentgateway's MCP authentication |
| Registry | **More platform connectors**: import agents from cloud agent platforms and SaaS agent builders (AWS, Google, Salesforce, Databricks) the way [Microsoft 365 and Copilot Studio](platforms.md) are, when someone needs one | Platform APIs |
| Registry | **Block platform agents from AgentGov**, once Microsoft's block API accepts an application rather than only a signed-in administrator | Microsoft Graph |
| Policy | **AuthZEN interface** so the decision point can be swapped (for example to Cedar) without touching enforcement points | OpenID AuthZEN |

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
