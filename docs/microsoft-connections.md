# Connecting AgentGov to Microsoft's services

AgentGov governs agents without any Microsoft service. In an organisation that uses
Microsoft 365, it can also use the services below. Each one is optional and adds
something to what AgentGov knows or can do. AgentGov uses the ones it can reach and works
without the others, and one that fails doesn't affect the rest.

The **Microsoft connections** card on the Platforms page (and `agentgov platforms
status`) shows each connection and how it is doing:

| Status | Meaning |
|---|---|
| Working | The last run succeeded |
| Waiting for its first run | Set up; it runs at the next sync |
| Missing a permission | AgentGov's app registration lacks the permission it needs: the card names it |
| Failing | The last run failed: the card shows Microsoft's error |
| Not set up | The card says what it needs |
| Ready for admins signed in with Entra ID | It runs when an admin signed in through Microsoft Entra ID asks for it |
| Import only | The Copilot Studio inventory, when admins don't sign in through Entra ID: import an export instead |
| Out of date | The connector allowlist changed since it was pushed to Power Platform |
| Monitoring, Enforcing | Copilot Studio threat detection's mode |
| Turned off in Features | An administrator turned the connection off on the [Features](features.md) page |

AgentGov works out what it has. Its app registration's access token lists the
application permissions an admin granted it, so AgentGov runs only the connections it
holds a permission for. Grant a permission later and AgentGov uses it once its access
token is renewed (tokens last about an hour), or at once when an admin asks for a sync.

| Connection | What AgentGov gets | What it needs |
|---|---|---|
| [Microsoft 365 agent catalog](platforms.md#microsoft-365-agent-catalog) | Agents in Microsoft 365 Copilot, with declarative agents' instructions | App permission `CopilotPackages.Read.All`; a Microsoft Agent 365 licence |
| [Copilot Studio inventory](platforms.md#copilot-studio-inventory) | Copilot Studio and Agent Builder agents, their settings and connectors | An admin signed in through Entra ID (or an exported file) |
| [Microsoft Entra Agent ID](#microsoft-entra-agent-id) | Agents' Entra identities, linked to their agents; agents only Entra knows about | App permission `AgentIdentity.Read.All` |
| [Microsoft Purview audit log](#microsoft-purview-audit-log) | Who uses each agent; jailbreak and cross-prompt injection attempts; makers' changes | App permission `AuditLogsQuery.Read.All` |
| [Microsoft Defender alerts](#microsoft-defender-alerts) | Microsoft's threat detections for agents, as findings | App permission `SecurityAlert.Read.All`; a Microsoft Agent 365 licence for agent detections |
| [Microsoft Entra access packages](#microsoft-entra-access-packages) | The access packages Entra assigns agents' identities, and issues before they expire; in manage mode, assigning and removing them | App permission `EntitlementManagement.Read.All` (to manage: `EntitlementManagement.ReadWrite.All`, or a catalog role); a Microsoft Agent 365 licence |
| [Power Platform connector policies](#pushing-the-connector-allowlist-into-power-platform) | The connector allowlist enforced by Power Platform | An admin signed in through Entra ID with the Power Platform administrator role |
| [Copilot Studio threat detection](#copilot-studio-threat-detection) | A decision from AgentGov's policies before each tool call a Copilot Studio agent makes | An HTTPS address Microsoft can reach; a Power Platform admin to connect it |

## AgentGov's app registration

The connections that read on a schedule share one Entra app registration, the one the
[Microsoft 365 catalog](platforms.md#microsoft-365-agent-catalog) uses
(`AGENTGOV_M365_TENANT_ID`, `AGENTGOV_M365_CLIENT_ID`, `AGENTGOV_M365_CLIENT_SECRET`). Add
the Microsoft Graph *application* permissions for the connections you want, and grant
admin consent:

| Permission | Connection |
|---|---|
| `CopilotPackages.Read.All` | Microsoft 365 agent catalog |
| `AgentIdentity.Read.All` | Microsoft Entra Agent ID |
| `AuditLogsQuery.Read.All` | Microsoft Purview audit log |
| `SecurityAlert.Read.All` | Microsoft Defender alerts |
| `EntitlementManagement.Read.All` | Microsoft Entra access packages (`EntitlementManagement.ReadWrite.All` also does, and lets AgentGov manage them) |

They run every `AGENTGOV_M365_SYNC_INTERVAL_SECONDS` (an hour by default). **Sync all**,
each connection's **Sync now**, or `agentgov platforms sync [CONNECTION]` run them at
once. A sync someone asks for also picks up a permission granted since the last one.

## Microsoft Entra Agent ID

AgentGov reads every agent identity in the tenant
(`GET /v1.0/servicePrincipals/microsoft.graph.agentIdentity`). Each identity is linked to
the agent the other sources report under the same Entra agent ID: the Copilot Studio
inventory's `entraAgentId` and the catalog's `agentIdentityId`. An agent identity's
object ID and app ID are the same, so either works. Identities that no other source
reports, such as agents in Microsoft Foundry projects AgentGov doesn't read ([other
platforms](other-platforms.md#microsoft-foundry)) or your own agents with an Entra agent
ID, become discovered agents of their own (source `platform:entra-agent-id`).

The agent's page shows its identity: whether it is enabled, the blueprint it was created
from (Copilot Studio's is named), and when. Identities deleted from Entra stay in the
registry, marked as gone. If Microsoft disables an identity (for a violation of its
services agreement), AgentGov raises an `entra.disabled_by_microsoft` finding, which adds
25 points to the agent's risk score and resolves itself when Microsoft enables it again.

AgentGov doesn't read identities' sponsors: Microsoft Graph lists them only for apps that
may also change every agent identity (`AgentIdentity.ReadWrite.All`).

## Microsoft Purview audit log

Each sync searches the audit log twice
(`POST /v1.0/security/auditLog/queries`):

* **Copilot interactions** (operation `CopilotInteraction`): someone used an agent.
  AgentGov records when each agent was last used, who used it lately (up to ten people)
  and in which apps (Teams, Outlook, and so on), and counts each interaction as one of the
  agent's model calls. When Microsoft detected a jailbreak attempt in a conversation, the
  agent gets an `agent.jailbreak_attempts` finding and a risk signal. When it detected a
  cross-prompt injection attempt in a file or message the agent read, the agent gets an
  `agent.cross_prompt_injection` finding and a prompt-injection risk signal.
* **Copilot Studio makers' changes** (`BotCreate`, `BotDelete`,
  `BotUpdateOperation-BotPublish`, `BotUpdateOperation-BotShare`,
  `BotUpdateOperation-BotAuthUpdate`): each becomes a ledger entry
  (`platform.agent_created`, `platform.agent_published`, `platform.agent_shared`,
  `platform.agent_deleted`, `platform.agent_authentication_changed`) with the maker as its
  actor (`maker:dana@contoso.com`).

Audit searches take minutes, so a sync doesn't wait for them. It collects the searches the
previous sync started and starts the next ones. With hourly syncs, an interaction shows
up about two hours after it happened. Searches stop an hour short of the present, because
records reach the audit log late. Purview accepts about 200 searches a day per tenant,
and AgentGov uses two per sync. A search that fails is run again, and one still not
finished after six hours is given up and run again.

Records name agents in several ways (for example `CopilotStudio.Declarative.<id>`).
AgentGov matches them against every ID the inventory, the catalog and Entra Agent ID
reported. Records it cannot match are counted and not stored. Copilot and Copilot Studio
records are part of Microsoft Purview Audit (Standard).

## Microsoft Defender alerts

Each sync reads the alerts created or updated since the last one
(`GET /v1.0/security/alerts_v2`; the first sync reads the last seven days) and keeps those
about agents: alerts with AI agent evidence, or from Microsoft's security for AI. Each one
becomes a `defender.alert` finding on the agent it names, with Defender's severity, its
recommended actions and a link to the alert. Open alerts add 20 points to the agent's
risk score. When Defender resolves an alert, AgentGov resolves the finding.

Since 1 July 2026, Microsoft's threat detections for Copilot Studio and Foundry agents
need a Microsoft Agent 365 licence. Without one, this connection still works, but finds no
alerts about agents.

## Microsoft Entra access packages

Microsoft Entra ID Governance can give agents' Entra identities access for a while, as it
does people: an access package bundles security group memberships, API permissions and
Entra roles, and an assignment of it ends on a date unless someone extends it. Agents'
sponsors and owners ask for packages for their agents in My Access, and administrators
assign them directly ([Microsoft's documentation][agent-access-packages]). This is
separate from AgentGov's own [access packages](access-packages.md), which grant what
AgentGov's gateway governs.

The **entra-access-packages** feature decides what AgentGov does with them:

| Mode | What AgentGov does |
|---|---|
| `inform` (default) | Reads the packages agents can hold and what each agent's identity holds, and raises issues. It writes nothing into Entra |
| `manage` | Also lets administrators assign packages to agents and remove them, from AgentGov |
| `off` | Nothing, even where it could read them |

**Reading.** Each sync lists the access packages with their assignment policies
(`GET /v1.0/identityGovernance/entitlementManagement/accessPackages?$expand=assignmentPolicies`),
keeps those with a policy for agents (all agents, or service principals), and reads each
one's assignments (`GET …/assignments?$filter=accessPackage/id eq '…'&$expand=target`). An
assignment whose target is an agent's Entra identity shows on the agent's page, with its
state and when it ends. Assignments to identities no agent is linked to are counted, not
kept.

**Issues.** Two weeks before an assignment ends, AgentGov raises an `entra.access_expiring`
[issue](issues.md) about the agent, from low severity to high on its last day, which goes
to the agent's owner, then its sponsors, then its team. One Entra couldn't deliver raises
`entra.access_failed`. They close once two syncs in a row find them gone (extended,
removed or delivered after all), and are marked unverified while the sync fails. Entra
also tells sponsors before an assignment expires; AgentGov's issue goes up the chain until
someone acts.

**Managing.** In manage mode, an administrator assigns a package to an agent (the agent's
page → *Entra access packages* → **Assign**, or `agentgov platforms entra-assign AGENT
PACKAGE`) and removes one (**Remove in Entra**, or `agentgov platforms entra-remove AGENT
ASSIGNMENT`). AgentGov asks Entra as its app, through the package's policy for agents
(`POST …/assignmentRequests` with `adminAdd` or `adminRemove`), and records each request
in the ledger (`entra.access_requested`, `entra.access_removal_requested`). Entra delivers
it or refuses, and the next sync shows which. The app needs
`EntitlementManagement.ReadWrite.All`, or the **Access package assignment manager** role in
the packages' catalogs, which Entra doesn't put in the app's token: then the Microsoft
connections card says AgentGov can't tell, and Entra's answer says whether it may.

Agent identities in access packages need a Microsoft Agent 365 licence, with at least
Microsoft Entra P1 or Microsoft 365 E3, or Microsoft 365 E7; Microsoft lists it as a
preview ([licensing][entra-licensing]).

## Pushing the connector allowlist into Power Platform

On its own, the [connector allowlist](platforms.md#connector-allowlist) raises findings
for agents that use other connectors; it doesn't stop them. Power Platform's [advanced
connector policies][acp] do: a policy lists the connectors allowed, and Power Platform
blocks every other one, at design time and at run time.

An admin signed in through Entra ID can push the allowlist into Power Platform with
**Push to Power Platform** on the Platforms page (or `agentgov platforms
push-connector-policy`). AgentGov keeps one policy, *AgentGov connector allowlist*, that
allows exactly the approved connectors, with all their actions. It applies the policy, as
the admin, to the environment groups and environments the admin picks.

A connector policy applies to **every app, flow and agent** in those environments, not
only to agents. So AgentGov is careful with it:

* It shows first what a push would do: the connectors it will allow, the agents that
  would lose connectors, and where another policy already applies (`agentgov platforms
  connector-policy` shows the same).
* It never applies its policy where another connector policy applies. An environment
  takes one, so remove the other policy first, or add the connectors to it there.
* It refuses to push an empty allowlist, which would block every connector.
* It never pushes on its own. After the allowlist changes, the connection shows *Out of
  date* until an admin pushes again.
* Every push is in the ledger (`connector_policy.pushed`), with the connectors and the
  groups and environments the admin picked. If applying the policy fails part way, what
  was done is recorded too.

The policy is one object in Power Platform, so a push changes its list everywhere it
already applies, not only where the admin picks this time.

Power Platform runs connector policies alongside classic data policies, and the more
restrictive of the two wins. Connector policies cover certified connectors and MCP
servers. Custom and HTTP connectors, and Copilot Studio's own connectors (such as its
knowledge sources and channels), still need classic data policies. Environment groups
hold managed environments only. To undo a push, remove the rule in the Power Platform
admin center (**Environment groups** > the group > **Rules** > **Advanced connector
policies** > **Remove rule**), then on each environment it reached.

The admin needs the Power Platform administrator role, and AgentGov's sign-in app
registration the Power Platform API's delegated permission
`EnvironmentManagement.Groups.Read`.

## Copilot Studio threat detection

Copilot Studio can ask an outside service before each tool call an agent makes ([external
threat detection][threat-detection]). Connected to AgentGov, it sends the tool, its
inputs, the earlier tool results in the plan and who is using the agent. AgentGov decides
with its policies and the registry, using the same OPA that decides for the gateway
(`data.agentgov.copilotstudio.decision`). It blocks the call when:

* the agent is blocked in AgentGov, so **Block** in AgentGov now stops a Copilot Studio
  agent's tool calls;
* the agent's risk is critical (the `risk-based-access` control);
* the tool uses a connector that isn't on the allowlist (once the allowlist lists one,
  and when Copilot Studio names the connector in the tool's definition), while the
  `connector-allowlist` control is enforced; monitored, the call goes through and is
  recorded ([what happens](platforms.md#when-an-agent-uses-a-connector-that-isnt-approved));
* the inputs contain credentials (the `data-protection` control);
* an earlier tool result in the plan tried to give the agent instructions (indirect
  prompt injection, the `prompt-injection` control);
* an [organisation policy](policies.md) denies it. Their `deny` rules apply here too, and
  `input.platform` is `copilot-studio`.

Every decision is in the ledger (`decision.copilot_studio`) with the tool, the
environment, the user and Copilot Studio's correlation ID. It also counts towards the
agent's activity and risk, and raises findings for credentials and injected instructions.
A Copilot Studio agent that AgentGov doesn't know yet is allowed, with a finding asking
for the inventory to be synced.

The controls named above apply as their [features](features.md) say: one in monitor mode
only records what it would have done (`monitored` in the ledger entry). Threat detection
itself is the feature `copilot-studio-threat-detection`, off until you choose a mode:

* `monitor` never blocks. AgentGov records what its policies would have decided
  (`would_block` in the ledger, and a count on the Platforms page). Start here.
* `enforce` blocks what the policies deny. Copilot Studio stops the agent and tells the
  user that AgentGov's policies blocked the action.

Copilot Studio waits less than a second for an answer, and then lets the tool run, unless
the admin chose to block when the provider fails. AgentGov decides from data it already
holds and records the evidence after answering. When it cannot decide in time (OPA is
unreachable), it answers as `AGENTGOV_COPILOT_STUDIO_ON_ERROR` says: `block` (the
default) or `allow`. Microsoft asks only about agents that use generative orchestration,
not classic ones.

### Setting it up

1. **Make AgentGov reachable.** Copilot Studio calls from Microsoft's cloud, so
   `AGENTGOV_PUBLIC_URL` must be an HTTPS address it can reach. The endpoint is
   `<AGENTGOV_PUBLIC_URL>/integrations/copilot-studio`.
2. **Expose an API on AgentGov's app registration.** The sign-in app registration will
   do. Under **Expose an API**, set the application ID URI to the origin of
   `AGENTGOV_PUBLIC_URL`, for example `https://agentgov.contoso.com`. Copilot Studio asks
   Entra for tokens for it.
3. **Create the app registration Copilot Studio calls with.** Microsoft's script
   creates it with the federated credential Copilot Studio needs:
   `Create-CopilotWebhookApp.ps1 -TenantId <tenant ID> -Endpoint
   https://agentgov.contoso.com/integrations/copilot-studio` (see [Microsoft's
   steps][threat-detection]). Note its application (client) ID.
4. **Configure AgentGov**, restart it, then turn the feature
   `copilot-studio-threat-detection` to monitor on the **Features** page (or with
   `agentgov features set copilot-studio-threat-detection monitor`):

   ```bash
   AGENTGOV_COPILOT_STUDIO_CALLER_APP_IDS=<the app ID from step 3>
   AGENTGOV_OPA_URL=http://opa:8181    # already set in the reference deployment
   ```

   AgentGov takes the tenant from `AGENTGOV_M365_TENANT_ID` or the Entra sign-in issuer
   when either is the tenant ID; otherwise set `AGENTGOV_COPILOT_STUDIO_TENANT_ID`. If the
   API's application ID URI isn't the origin of `AGENTGOV_PUBLIC_URL`, or Entra issues it
   v2.0 tokens, list the accepted audiences (the URI, or the API's client ID) in
   `AGENTGOV_COPILOT_STUDIO_AUDIENCES`.
5. **Connect each environment.** In the Power Platform admin center, go to **Security** >
   **Threat detection** > **Additional threat detection**, select the environment and
   **Set up**. Tick **Allow Copilot Studio to share data with a threat detection
   provider**, enter the app ID from step 3 and the endpoint from step 1, and choose what
   happens when AgentGov doesn't answer. Saving checks that AgentGov answers. Microsoft
   offers no way to do every environment at once.
6. **Watch, then enforce.** Leave it in `monitor` while you look at what AgentGov would
   block (Platforms > Microsoft connections, and the ledger's `decision.copilot_studio`
   entries). Then set the feature to enforce.

AgentGov accepts a call only with a token that Microsoft Entra ID signed for this tenant,
for AgentGov's API, and for one of the apps in `AGENTGOV_COPILOT_STUDIO_CALLER_APP_IDS`.

## Doing it from the CLI or the API

| Task | Admin UI | CLI | API |
|---|---|---|---|
| See every connection and its state | Platforms > Microsoft connections | `agentgov platforms status` | `connections` in `GET /v1/platforms` |
| Sync every app connection | Microsoft connections > **Sync all** | `agentgov platforms sync` | `POST /v1/platforms/sync` |
| Sync one | Microsoft connections > **Sync now** | `agentgov platforms sync entra-agent-id\|purview-audit\|defender\|entra-access-packages\|microsoft-365` | `POST /v1/platforms/{connection}/sync` |
| See agents' Entra access packages | The agent's page > *Entra access packages* | `agentgov platforms entra-access [--agent A]` | `GET /v1/platforms/entra-access-packages`, `GET /v1/agents/{ref}/entra-access-packages` |
| Assign or remove one (manage mode) | *Entra access packages* > **Assign**, **Remove in Entra** | `agentgov platforms entra-assign AGENT PACKAGE`, `agentgov platforms entra-remove AGENT ASSIGNMENT` | `POST /v1/agents/{ref}/entra-access-packages/assign`, `DELETE /v1/agents/{ref}/entra-access-packages/{assignment}` |
| See what pushing the allowlist would do | Connectors > **Push to Power Platform** | `agentgov platforms connector-policy` | `GET /v1/platforms/connector-policy` |
| Push the allowlist to Power Platform | Connectors > **Push to Power Platform** | `agentgov platforms push-connector-policy --group ID [--environment ID]` | `POST /v1/platforms/connector-policy` |
| See threat detection's decisions | Ledger, type `decision.copilot_studio` | `agentgov ledger tail --type decision.copilot_studio` | `GET /v1/ledger?type=decision.copilot_studio` |

Syncing and pushing need an admin. Pushing, like the Copilot Studio inventory sync, needs
an admin signed in through Microsoft Entra ID (`agentgov login` in the CLI).

[acp]: https://learn.microsoft.com/en-us/power-platform/admin/advanced-connector-policies
[agent-access-packages]: https://learn.microsoft.com/en-us/entra/agent-id/agent-access-packages
[entra-licensing]: https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals
[threat-detection]: https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider
