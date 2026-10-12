# Microsoft Agent 365 baseline and parity matrix

AgentGov uses [Microsoft Agent 365](https://learn.microsoft.com/en-us/microsoft-agent-365/overview)
as its functional baseline: the capabilities an enterprise needs to run AI agents
safely. This page summarises what Agent 365 offers (as of October 2026), maps each
capability to AgentGov, and names the open-source building block that provides it.

Legend: ✅ available · 🟡 partial · ⏳ [roadmap](roadmap.md) · ➖ out of scope

## Agent 365 in one paragraph

Agent 365 was announced at Ignite 2025 as "the control plane for AI agents" and became
generally available on 1 May 2026 ($15 per user per month, or bundled in Microsoft 365 E7).
It extends Microsoft 365 administration to agents: a **registry** of every agent, **Entra Agent
ID** identities with owners and sponsors, **Conditional Access** and ID Protection for agents,
dashboards and an agent map, governed **MCP tooling servers**, and **Defender / Purview**
protection (runtime blocking, DLP, audit). Microsoft now describes it as *Observe, Govern,
Secure*; the original five pillars (Registry, Access Control, Visualization,
Interoperability, Security) are used below because they map cleanly onto components.

Its gaps are what an open alternative can address: full value requires Entra registration
and a Microsoft 365 tenant, Conditional Access does not cover API-key access, runtime
blocking mostly covers Microsoft surfaces, licensing is per user (including sponsors and
users who delegate to agents), and much of it is preview with frequent API changes.

## Parity matrix

### Registry

| Agent 365 capability | AgentGov | How |
|---|---|---|
| Inventory of all agents with owner, publisher, platform, status | ✅ | Registry API, UI and manifests (`Agent` with owner, sponsors, framework, platform, models, environment, labels, A2A agent card) |
| Status: Available / Blocked / Draft / Not activated | ✅ | `active` / `blocked` / `pending` / `discovered`, plus soft-`deleted` |
| Requests: pending review, approve, reject | ✅ | Registrar-role API keys create `pending` agents; admins approve |
| Block / unblock, delete with 30-day restore | ✅ | Lifecycle actions; soft delete, restorable for 30 days, then purged automatically (or with `purge` sooner) |
| Agents without owners, agents at risk (registry tiles) | ✅ | Overview tiles and posture findings |
| Unmanaged / shadow agents | ✅ | Discovery from OpenTelemetry spans, gateway callers (monitor mode) and scanner imports (`/v1/discovery/import`, e.g. the Agent Governance Toolkit's `agent-discovery`) |
| IT-approved agent blueprints | ✅ | `Blueprint`: permissions, risk tier, sponsor requirement, attestation period, labels |
| Management rules (e.g. block ownerless agents without usage) | ✅ | [Management rules](management-rules.md): conditions (no activity, no owner or sponsor, attestation overdue, open findings, risk, status) and an action (an issue, an owner, block, delete, revoke access packages), previewed before they run; beyond Agent 365's (preview), each agent's people are told before a rule acts, rules can be monitored first, and a rule acts on a few agents at once at most. Agents on Microsoft 365 are told about, not blocked: blocking them needs a signed-in administrator |
| Agents built in Microsoft 365 Copilot, Copilot Studio and Agent Builder | ✅ | The Microsoft 365 agent catalog synced from Microsoft Graph, the Copilot Studio inventory imported from the Power Platform inventory or synced as the signed-in admin, and agent identities from Microsoft Entra Agent ID ([platforms](platforms.md)) |
| Block Microsoft 365 and Copilot Studio agents | 🟡 | Admins signed in through Entra ID quarantine Copilot Studio agents and block Microsoft 365 agents from AgentGov, which calls Microsoft's admin APIs as them ([platforms](platforms.md#acting-as-the-signed-in-admin)); with Copilot Studio threat detection enforcing, a Copilot Studio agent blocked in AgentGov can't call tools ([connections](microsoft-connections.md#copilot-studio-threat-detection)); otherwise, block them in Microsoft's admin centers |
| Registry sync from AWS, Google, Salesforce, Databricks, … | ⏳ | More platform connectors on the roadmap; OTel discovery covers instrumented agents today |
| Agent store / catalog for end users | ➖ | AgentGov governs agents; it is not a distribution channel |
| A2A-shaped agent records (agent cards) | ✅ | Agents carry an A2A v1.0 `agent_card` |

### Identity and access control (Entra Agent ID, Conditional Access)

| Agent 365 capability | AgentGov | How |
|---|---|---|
| A distinct identity per agent | ✅ | **Keycloak**: one confidential OAuth client per agent, provisioned by the control plane |
| Agent identity blueprint holding inheritable permissions | ✅ | Blueprint grants are inherited by every agent that uses it |
| Owners and sponsors (sponsor required) | ✅ | Activation requires a sponsor unless the blueprint waives it |
| Autonomous (app-only) token flow | ✅ | OAuth client credentials; tokens carry `agent_id` and the gateway audience |
| On-behalf-of user flow | ✅ | Agents exchange a person's token for one of their own (Keycloak's token exchange, RFC 8693, or its delegation preview with `act`); blueprints say whom their agents act for, and policy, the ledger and approvals see the person and their groups ([acting for people](acting-for-people.md)) |
| Secretless credentials (federated identity credentials) | ✅ | Agents authenticate with their workload's own token instead of a client secret: Kubernetes service account tokens, SPIFFE JWT-SVIDs, or tokens from Entra Agent ID and other OpenID Connect issuers, through Keycloak's federated client authentication; blueprints can require it, and blocking an issuer stops its agents ([agents' own identities](agent-identity.md)) |
| Credential rotation | ✅ | `POST /v1/agents/{id}/credentials {"rotate": true}` |
| Entra Agent ID identities of agents built on Microsoft's platforms | ✅ | Read from Microsoft Graph and linked to their registry agents; an identity Microsoft disabled raises a finding ([connections](microsoft-connections.md#microsoft-entra-agent-id)) |
| Conditional Access for agents | ✅ | **OPA** policies evaluated on every tool call, model call and call between agents, with registry context |
| Report-only mode for access policies | ✅ | Each control at the gateway can run in monitor mode: it decides and records, but doesn't stop the call ([features](features.md)) |
| Risk-based access (ID Protection "risky agents") | ✅ | Risk score from posture and runtime signals; critical risk is blocked by the baseline policy; optional auto-block |
| Access reviews / sponsor attestation | ✅ | Periodic attestation by sponsors; expiry raises findings |
| Access packages for agents | ✅ | AgentGov's own [access packages](access-packages.md): tools, models and agents to call, held for a while once someone other than the requester approves, with reminders, renewals, reviews and expiry at the gateway (monitored by default, enforced when you choose); and Microsoft Entra's access packages for agents' Entra identities, read with issues before they expire, and assigned or removed from AgentGov in manage mode ([connections](microsoft-connections.md#microsoft-entra-access-packages)) |
| Sponsors and owners told about their agents' problems | ✅ | Findings go to an agent's owner, then its sponsors, then its team, by email and in their Teams or Slack channels, and escalate when nobody acknowledges them; people without an AgentGov role sign in to see and acknowledge their own ([issues](issues.md)) |
| Kill switch | ✅ | `block` disables the Keycloak client and denies at the gateway within a second (OPA long polling) |
| Administrators sign in with their organisation account; delegated admin roles | ✅ | Single sign-on to the admin UI and API through **Keycloak** (which can federate an existing directory); provider roles map to `admin`, `approver`, `secops`, `auditor`, `registrar` |

### Visualization and observability

| Agent 365 capability | AgentGov | How |
|---|---|---|
| Overview dashboard | ✅ | Admin UI overview: inventory, risk, approvals, findings, 14-day activity |
| Agent map (agents, users, tools) | ✅ | `/v1/graph` and the UI map: people → agents → tool servers and other agents, with call volumes |
| Telemetry via OpenTelemetry (invoke_agent / execute_tool / chat spans) | ✅ | **OTel Collector** → control plane; the same GenAI semantic conventions, so Agent 365-instrumented agents can report here |
| Trace exploration | ✅ | Optional **Langfuse** (`deploy/compose/docker-compose.langfuse.yml`): the collector sends it every agent and gateway trace, and each gateway decision in the ledger links to its trace |
| Usage and cost of agents' model calls | ✅ | Tokens and cost per agent, day, provider and model, metered from the gateway's access logs ([model calls](models.md)) |
| Audit of agent activity | ✅ | Hash-chained evidence ledger with verification and JSONL export, daily checkpoints time-stamped by an authority (RFC 3161), and retention you choose, with archives that verify offline ([evidence](evidence.md)), where Purview keeps audit records 180 days (Standard), a year (Premium) or up to ten years (an add-on); the use of Microsoft 365 and Copilot Studio agents, and Copilot Studio makers' changes, read from the Purview audit log ([connections](microsoft-connections.md#microsoft-purview-audit-log)) |

### Interoperability

| Agent 365 capability | AgentGov | How |
|---|---|---|
| Governed MCP tooling gateway | ✅ | **agentgateway** (Linux Foundation / AAIF), config generated from the registry |
| Tenant-wide tool allow/block | ✅ | Per-agent grants filter `tools/list`; servers can be blocked |
| Bring-your-own MCP server with admin approval | ✅ | Registrar-submitted tool servers start `pending` |
| MCP spec 2026-07-28 (stateless) | ✅ | Handled by agentgateway; decisions use the parsed body, never spoofable headers |
| Frameworks: Agent Framework, Semantic Kernel, OpenAI Agents SDK, Claude Agent SDK, LangChain, … | ✅ | Any MCP client works through the gateway; in-process enforcement via the **Agent Governance Toolkit** querying OPA (`data.agentos.allow`) |
| Governed model access, with token limits per consumer (Azure API Management's AI gateway) | ✅ | **agentgateway**'s LLM routes for approved model providers (OpenAI, Anthropic, Gemini, OpenAI-compatible), model grants on blueprints, provider keys held by the gateway and never by agents, and daily token budgets per agent ([model calls](models.md)) |
| Enterprise MCP registry for developers' MCP clients (GitHub Copilot with Azure API Center) | ✅ | Tool servers listed for developers, served as the MCP Registry API v0.1 for Copilot's *Registry only* mode, and as a managed-settings.json allowlist ([developer tools](developer-tools.md)) |
| Shadow MCP servers on developers' machines | ✅ | `agentgov mcp scan --report` inventories VS Code, Copilot, Claude, Cursor, Windsurf, Gemini CLI and Codex configurations without their credentials; servers that aren't approved, or that skip the gateway, raise findings |
| A2A traffic governance | ✅ | Calls between agents through agentgateway's A2A routes, each decided by OPA: who may call whom (`agent_access` on blueprints and agents), and the controls of tool calls. The agent called gets a delegation naming the agents that handed the work down and the person at their head, which its own calls carry on into policy and the ledger ([agent to agent](agent-to-agent.md)). Calls that go around the gateway, which AgentGov doesn't see, are looked for in telemetry and by an optional test, and agents can refuse them by checking the delegation ([calls around the gateway](agent-to-agent.md#calls-around-the-gateway)) |
| Work IQ MCP servers (Mail, Calendar, Teams, …) | ➖ | Microsoft 365-specific; any MCP server can be registered |
| CLI | ✅ | `agentgov` CLI |

### Security (Defender, Purview)

| Agent 365 capability | AgentGov | How |
|---|---|---|
| Real-time blocking of risky tool calls | ✅ | Governance processor via agentgateway's `ExtMcp` hook, fail-closed; Copilot Studio agents' tool calls through Copilot Studio's external threat detection, decided by the same OPA ([connections](microsoft-connections.md#copilot-studio-threat-detection)) |
| Secret exfiltration detection | ✅ | Credential detectors on tool arguments (deny) and results (redact) |
| Prompt injection (XPIA) protection | ✅ | Tool results and other agents' answers with injected instructions are withheld, and model calls whose conversation holds one are refused; found by heuristics and, optionally, by **IBM Granite Guardian** ([detection](detection.md)); jailbreak and XPIA attempts that Microsoft detects against Microsoft 365 and Copilot Studio agents become findings (Purview audit log) |
| Tool poisoning and definition drift | ✅ | Poisoned tools hidden; changed definitions refused until re-approved |
| DLP / sensitivity of personal data | ✅ | **Presidio** detects PII; policy redacts it from results, from other agents' answers, from calls to unverified servers and, as you choose, from messages between agents |
| Jailbreak detection in prompts (Azure AI Content Safety's Prompt Shields) | ✅ | The latest prompt from a person in each model call is checked with heuristics and, optionally, by IBM Granite Guardian; monitored by default, refused when enforced, and a finding either way ([model calls](models.md)) |
| DLP for prompts (Purview DLP for Microsoft 365 Copilot) | ✅ | Personal data masked in prompts to model providers that aren't verified; prompts with credentials refused, and answers with them withheld ([model calls](models.md)) |
| Posture assessment and recommendations | ✅ | Findings with remediation (ownerless, no sponsor, expired attestation, stale, broad grants, unverified servers, identity drift) |
| Harmful or malicious agent instructions | ✅ | Agents' system prompts (registered, reported in telemetry, or read from Microsoft 365) are checked by rules and optionally by **IBM Granite Guardian**; problems become findings and add to the risk score ([instructions](instructions.md)) |
| Connectors used by Copilot Studio agents; risky agent settings | ✅ | Connector allowlist with findings for agents that use other connectors, publish without authentication, use their maker's connections or are shared with everyone; enforced by pushing it into Power Platform's advanced connector policies, and by Copilot Studio threat detection ([connections](microsoft-connections.md#pushing-the-connector-allowlist-into-power-platform)) |
| Human approval for sensitive actions | ✅ | Destructive tools (and any policy you write) route to an approver, or to the person the agent acted for; single-use approvals ([acting for people](acting-for-people.md#approvals-sent-to-the-person)) |
| Alerts / incidents | ✅ | Findings, with alerts in Teams and Slack; Defender's alerts about agents become findings ([connections](microsoft-connections.md#microsoft-defender-alerts)); the ledger to SIEMs as OCSF events, and the security team's tools may triage, contain or decide as far as you choose ([security operations](secops.md)) |
| Compliance assessments (Purview Compliance Manager: EU AI Act, ISO/IEC 42001, NIST AI RMF) | ✅ | Reports for the same three frameworks, control by control, with what is in place and the evidence, and an evidence pack for assessors ([evidence](evidence.md)) |
| Retention policies | ✅ | The ledger kept for at least six months, then archived; operational records kept for a period you choose ([evidence](evidence.md#retention)) |
| Insider risk, eDiscovery | ➖ | Outside AgentGov; the ledger export and the evidence pack provide evidence |

## Sources

Microsoft documentation and announcements, checked October 2026:

- [Agent 365 overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview) ·
  [Ignite 2025 announcement](https://www.microsoft.com/en-us/microsoft-365/blog/2025/11/18/microsoft-agent-365-the-control-plane-for-ai-agents/) ·
  [GA announcement](https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations/)
- Registry: [agent registry](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-registry),
  [agent actions](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-actions),
  [agent settings and management rules](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-settings),
  [connected platforms](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/connected-platforms)
- Identity: [Entra agent blueprints](https://learn.microsoft.com/en-us/entra/agent-id/agent-blueprint),
  [owners, sponsors, managers](https://learn.microsoft.com/en-us/entra/agent-id/agent-owners-sponsors-managers),
  [Conditional Access for agents](https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id),
  [risky agents](https://learn.microsoft.com/en-us/entra/id-protection/concept-risky-agents)
- Observability: [attribute reference](https://learn.microsoft.com/en-us/microsoft-agent-365/developer/observability-attribute-reference),
  [concepts](https://learn.microsoft.com/en-us/microsoft-agent-365/developer/observability-concepts)
- Tools: [tooling servers](https://learn.microsoft.com/en-us/microsoft-agent-365/tooling-servers-overview),
  [bring-your-own MCP servers](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/manage-byo-mcp-server)
- Security: [Defender real-time protection](https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-real-time-protection),
  [Purview for Agent 365](https://learn.microsoft.com/en-us/purview/ai-agent-365),
  [Purview DLP for Microsoft 365 Copilot](https://learn.microsoft.com/en-us/purview/dlp-microsoft365-copilot-location-learn-about),
  [audit log retention](https://learn.microsoft.com/en-us/purview/audit-log-retention-policies),
  [Compliance Manager assessments](https://learn.microsoft.com/en-us/purview/compliance-manager-assessments)
- Developer tools: [restricting Copilot to an MCP registry](https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-mcp-server-access),
  [MCP allowlists in enterprise managed settings](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-enterprise-allowlist)
- Models: [AI gateway capabilities in Azure API Management](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities),
  [Prompt Shields](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection)
- Connections: [Entra agent identities](https://learn.microsoft.com/en-us/graph/api/resources/agentidentity),
  [Purview audit log queries](https://learn.microsoft.com/en-us/graph/api/security-auditcoreroot-post-auditlogqueries),
  [Defender alerts](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2),
  [advanced connector policies](https://learn.microsoft.com/en-us/power-platform/admin/advanced-connector-policies),
  [Copilot Studio external threat detection](https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider)
- Licensing: [service description](https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-agent-365/microsoft-agent-365),
  [licensing FAQ](https://www.microsoft.com/licensing/faqs/122)
- Microsoft's own open-source complement: [Agent Governance Toolkit reference architecture](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/a365-agt-reference-architecture.md)
