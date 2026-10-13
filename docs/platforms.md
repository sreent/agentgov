# Agents on Microsoft 365 and Copilot Studio

In an organisation that uses Microsoft 365, most agents don't call tools through
AgentGov's gateway. People build them in Copilot Studio or Agent Builder, or install
them from partners, and they run inside Microsoft 365. AgentGov's gateway can't sit in
front of these agents, but AgentGov can govern what Microsoft reports about them. The
**Platforms** page (and `agentgov platforms`) brings three sources into the registry:

* the organisation's **Microsoft 365 agent catalog**, synced from Microsoft Graph;
* the **Copilot Studio inventory**: Copilot Studio and Agent Builder agents, imported
  from the Power Platform inventory together with the connectors each one uses;
* **Microsoft Entra Agent ID**: the tenant's agent identities, linked to the agents
  above, plus agents built elsewhere that have one, such as in Microsoft Foundry projects
  AgentGov doesn't read
  ([details](microsoft-connections.md#microsoft-entra-agent-id)).

Each agent becomes a registry agent with the source `platform:microsoft-365`,
`platform:copilot-studio` or `platform:entra-agent-id`. It starts unmanaged (`discovered`), with an
"agent to review" issue. Adopt it to give it an owner, sponsors and periodic
attestation, like any other agent. AgentGov issues these agents no gateway credentials
and doesn't apply blueprints to them, because they never call the gateway. When more than
one source reports the same agent (a Copilot Studio agent published to Microsoft 365, and
its Entra agent identity), AgentGov matches them by Entra agent ID.

Agents built on AWS, Google Cloud, Salesforce, Databricks and Microsoft Foundry are read the
same way, by connectors of AgentGov's own ([other platforms](other-platforms.md)); a Foundry
agent and its Entra agent identity are one agent.

Microsoft's other services can tell AgentGov more, or let it act: the Purview audit log
(who uses each agent, and attacks on them), Defender's alerts, Power Platform's connector
policies and Copilot Studio's threat detection. Each one is optional, and AgentGov works
with whichever it can reach. [Connecting AgentGov to Microsoft's
services](microsoft-connections.md) covers them all.

**On its own, AgentGov reads these platforms; it doesn't change them.** Blocking or
deleting one of these agents in AgentGov records the decision in the registry and the
ledger, but the agent keeps running. To stop it, block it in its platform as well: in the
Microsoft 365 admin center (**Agents**), in the Power Platform admin center (**Manage >
Inventory**), or from AgentGov itself if admins sign in through Microsoft Entra ID (see
[Acting as the signed-in admin](#acting-as-the-signed-in-admin)). Microsoft's APIs for
blocking agents accept only a signed-in administrator, not an application, so AgentGov
can only block an agent on behalf of an admin who signed in. Until someone does, an issue
asks the agent's people to stop it there, and closes once a sync shows it stopped ([Blocked
in AgentGov, still running](#blocked-in-agentgov-still-running)). With [Copilot Studio
threat detection](microsoft-connections.md#copilot-studio-threat-detection) enforcing,
blocking a Copilot Studio agent in AgentGov also stops its tool calls, because Copilot
Studio asks AgentGov before each one.

## Microsoft 365 agent catalog

AgentGov reads the catalog through the Microsoft Graph [Package Management
API][packages], as an application, so nobody needs to be signed in. It lists the
packages that Microsoft 365 Copilot can host
(`GET /v1.0/copilot/admin/catalog/packages?$filter=supportedHosts/any(h:h eq 'Copilot')`).
Microsoft requires a Microsoft Agent 365 licence for this API. Without one, don't grant
the permission below: AgentGov then leaves the catalog out, and the Copilot Studio import
below works without it.

1. In the Microsoft Entra admin center, register an application (**App registrations >
   New registration**).
2. Under **API permissions**, add the Microsoft Graph *application* permission
   `CopilotPackages.Read.All`, then grant admin consent.
3. Under **Certificates & secrets**, create a client secret.
4. Give the control plane the tenant, the application (client) ID and the secret. With
   Docker Compose, put them in `deploy/compose/.env`:

   ```bash
   AGENTGOV_M365_TENANT_ID=contoso.onmicrosoft.com   # or the tenant ID
   AGENTGOV_M365_CLIENT_ID=00000000-0000-0000-0000-000000000000
   AGENTGOV_M365_CLIENT_SECRET=...
   ```

The control plane syncs when it starts and every hour after that
(`AGENTGOV_M365_SYNC_INTERVAL_SECONDS`; `0` syncs only on demand). Admins can sync at any
time with **Sync now** or `agentgov platforms sync microsoft-365`. A failed sync is shown
on the Platforms page with Microsoft's error. The same app registration can also read
Entra Agent ID, the Purview audit log and Defender's alerts, each with a permission of its
own ([AgentGov's app registration](microsoft-connections.md#agentgovs-app-registration)).

By default AgentGov imports agents built in your organisation (`custom`), shared by
their users (`shared`) and installed from partners (`external`), but not Microsoft's own.
Set `AGENTGOV_M365_PACKAGE_TYPES` to a comma-separated list of `custom`, `shared`,
`external` and `microsoft` to change that.

For each agent AgentGov records:

* its type and publisher;
* who it is available and deployed to;
* whether it is blocked in Microsoft 365;
* any pending request, such as a user asking for it to be published;
* its Entra agent ID and version.

Agents that disappear from the catalog stay in the registry, marked as no longer in the
catalog, so their history is kept. Delete them in AgentGov when you no longer need the
record.

## Copilot Studio inventory

The Power Platform inventory lists every Copilot Studio and Agent Builder agent with
its settings and the [connectors it uses][inventory-schema]. Microsoft only lets a
signed-in person query it (an application gets HTTP 403). If admins sign in to AgentGov
through Microsoft Entra ID with [admin actions](#acting-as-the-signed-in-admin) turned
on, **Sync now** on the Platforms page (or `agentgov platforms sync copilot-studio`)
reads it as the admin who asks. Otherwise an administrator exports it and imports the
file:

```bash
az login
az graph query --first 1000 -o json \
  -q "PowerPlatformResources | where type == 'microsoft.copilotstudio/agents'" \
  > copilot-studio-agents.json
agentgov platforms import copilot-studio-agents.json
```

Or use **Import inventory** on the Platforms page. Some notes on the export:

* **Roles.** The account needs a Microsoft Entra role that can read the inventory:
  Power Platform administrator, AI administrator, AI reader, Global reader, Dynamics 365
  administrator or Global administrator.
* **Azure CLI extension.** `az graph query` needs the Azure CLI's `resource-graph`
  extension (`az extension add --name resource-graph`).
* **More than 1,000 agents.** Export them in pages with `--skip-token` and import the
  files together (`agentgov platforms import page1.json page2.json ...`). Importing is
  idempotent: agents already in the registry are updated.
* **Other ways to export.** The same rows come from the [Power Platform inventory
  API][inventory-api] (`POST https://api.powerplatform.com/resourcequery/resources/query`)
  and from `pac resource-query query-resources`. AgentGov accepts either a JSON list of
  rows or an object with a `data` list.

Sync or import again whenever you want AgentGov to catch up, for example after each
review. AgentGov can't do it on a schedule, because Microsoft needs a signed-in person.
A sync reads the whole inventory, so agents missing from it are gone from Copilot Studio:
they stay in the registry, marked gone, their Copilot Studio issues close, and they are
no longer counted among the agents to review. An import does the same only when you say
the export is the whole inventory, every environment (**This is the whole inventory** on
the **Platforms** page, or `agentgov platforms import --complete`, with every page of a
larger export at once); otherwise agents missing from it are left as they were, because an
export may cover only some environments. An export with no agents in it marks none gone.
An agent seen again is back. Delete the record of a gone agent once you no longer need it.

## Who made each agent

The inventory names each agent's owner in Copilot Studio and its maker, by their
Microsoft Entra object IDs; Databricks names who created its agents by email address.
AgentGov shows them on the agent's page (**Owner and sponsors**) and in the agents list,
and adopting an agent suggests its owner on the platform, or its maker when the owner
can't take it, as its owner and sponsor. To show people rather than IDs, AgentGov looks
them up in Microsoft Entra ID, in whichever way it can:

* **With its app registration** (the `entra-users` connection on the Platforms page):
  the Graph application permission `User.Read.All`, with admin consent. `User.ReadBasic.All`
  is enough to know who people are, but not whose account is disabled.
* **As the admin who syncs the inventory**: an admin signed in through Microsoft Entra ID
  looks up the people the sync names, with the delegated permission `User.ReadBasic.All`
  (see [Setting it up](#setting-it-up)). That doesn't say whose account is disabled.
* **From a list of users.** In the Microsoft Entra admin center, **Users** > **Download
  users** gives a CSV of every user's object ID, name and email address; any user may
  download it. Upload it with **Upload users** on the Platforms page, or
  `agentgov platforms import-users users.csv`. A PowerShell export (`Get-MgUser -All |
  Export-Csv`) or Graph's JSON works too, as long as it has the `id` and `mail` (or
  `userPrincipalName`) of each user. A user missing from a list isn't taken to have left:
  the list may be filtered.

Without any of them, makers are shown by their Entra IDs, and whoever adopts an agent
names its owner. AgentGov looks up the owners and sponsors it names by email address the
same way. It looks up each person once, then again after a week: someone the directory
had and no longer has has left (a `person.left` entry in the ledger), isn't suggested any
more, and gets no more issues ([people who leave](issues.md#people-who-leave)). Turning
the `entra-users` feature off stops the lookups.

To adopt many agents at once, filter the Agents page (for example to one platform's
agents waiting to be adopted) and use **Adopt n agents**. Each becomes pending approval with
its maker as owner and sponsor where AgentGov knows them, or with the owner you give, such
as a team, for the others; those it can't adopt are listed with why. From the CLI:
`agentgov agents adopt --platform copilot-studio --makers --owner ai-governance`.

## Checks

AgentGov checks every imported Copilot Studio agent and raises an issue for each
problem it finds. An issue resolves itself when a later import shows the problem fixed.
Open issues count towards the agent's risk score: an agent's risk is what its settings
expose, and 10 points each for a missing owner and sponsor. An open issue of high severity
or worse makes it high risk at least, whatever its points add up to. Accepting an issue's
risk, or dismissing one that is wrong, takes it out of the score.

| Issue | Severity | Raised when the agent | Risk points |
|---|---|---|---|
| `platform.unapproved_connector` | High | uses a connector that isn't on the allowlist (only once the allowlist has a connector) | 20 |
| `platform.no_authentication` | High | is published with authentication set to *None*, so anyone who can reach a channel can use it | 25 |
| `platform.maker_credentials` | Medium | has tools that use its maker's connection, so every user reaches data with the maker's access | 10 |
| `platform.shared_with_everyone` | Medium | is shared with the whole organisation | 10 |

An agent waiting for review isn't riskier for it: that is its status, and nobody has
declared its risk tier yet. A shadow agent seen calling tools outside governance scores 30
points. How many of a platform's agents are left to review is one issue,
`platform.agents_to_review`, for the catch-all team, not one per agent: it says how many
and names a few, keeps count as they are adopted, and resolves when none is left.

## Connector allowlist

The **Connectors** table on the Platforms page lists every Power Platform connector
that Copilot Studio agents use. For each connector it shows:

* the agents that use it;
* the operations they call;
* how many of those operations run with the maker's connection;
* whether the connector is approved.

Approve the connectors your organisation allows, with a note on why. Until the first
connector is approved, nothing is flagged. After that, every agent that uses a connector
not on the list gets a `platform.unapproved_connector` issue. Approving or removing a
connector is recorded in the ledger and takes effect at once.

### When an agent uses a connector that isn't approved

What AgentGov does is yours to choose, from telling the agent's people to stopping it:

| What happens | When | How to choose |
|---|---|---|
| **It is flagged.** A `platform.unapproved_connector` issue, high severity, goes to the agent's owner, then its sponsors, then its team, by email and in their chats | At each inventory sync, once the allowlist lists a connector | On unless you turn the issue type off or change its severity ([kinds of issues](issues.md#kinds-of-issues)); who gets a message is up to the [issues](issues.md#fewer-messages) settings |
| **Its calls through that connector are refused** as they happen | Each tool call, while [Copilot Studio threat detection](microsoft-connections.md#copilot-studio-threat-detection) is enforced | The `connector-allowlist` control: enforce (the default) refuses them, monitor lets them through and records them, off doesn't check. It can differ for some agents ([exceptions](features.md#exceptions)), such as monitored in a pilot environment and enforced elsewhere |
| **It is blocked**, so it makes no tool calls at all | A management rule's days of notice after the rule told the agent's people | A rule on the issue, such as the example `unapproved-connectors` ([management rules](management-rules.md#examples)). It blocks Copilot Studio agents while threat detection is enforced, since Copilot Studio then asks AgentGov before each call; otherwise its issue says to quarantine the agent |
| **It is quarantined**: it stops working in every channel, though its makers can still test it | When an administrator does it | By hand: **Quarantine** on the agent's page, for an administrator signed in through Microsoft Entra ID ([below](#acting-as-the-signed-in-admin)), or in the Power Platform admin center. Microsoft's quarantine API takes a signed-in administrator only, so AgentGov can't quarantine an agent on its own |
| **Makers can't use the connector** in the first place | Once pushed | **Push to Power Platform** (`agentgov platforms push-connector-policy`): Power Platform blocks every other connector, as an [advanced connector policy](microsoft-connections.md#pushing-the-connector-allowlist-into-power-platform), on the environments an admin picks. It applies to apps and flows as well as agents, so AgentGov shows what it would do first |

Without threat detection or the pushed policy, the allowlist flags agents but stops
nothing: use Power Platform data policies (DLP) as well, and keep them consistent with the
allowlist. The **Connectors** table on the Platforms page says what happens to calls
through connectors that aren't approved, as things are set now.

## Blocked in AgentGov, still running

Most deployments read their platforms and can't change them: AgentGov's access is a
read-only app, an exported inventory, or no Microsoft admin who signs in. So blocking a
platform's agent in AgentGov hands the stop to the people who can do it, and checks that
they did:

1. Blocked in AgentGov while its platform still runs it, the agent gets a
   `platform.still_running` issue (high): "*sales-helper* is blocked in AgentGov but still
   runs in Copilot Studio". It goes to the agent's owner, then its sponsors, then its team,
   as every issue does ([issues](issues.md)), and through a service desk to theirs
   ([tickets](tickets.md)). It says who can stop the agent there and how, and holds the
   agent's IDs there (its environment, for a Copilot Studio agent).
2. Someone stops it in the platform, as the table below says.
3. The next sync or import shows it stopped, or gone, and the issue closes. The agent's
   page says *Blocked in AgentGov only* until then.

Unblocked or deleted in AgentGov, its issue closes too, whatever became of it (dismissed,
or its risk accepted): blocked again later, it is raised afresh. An agent stopped in a way
its platform doesn't report (its permissions taken away, say) stays "still running" to
AgentGov: dismiss the issue saying how it was stopped. Blocking it from AgentGov as a
signed-in admin ([below](#acting-as-the-signed-in-admin)) closes the issue at once.

| Platform | Who can stop it there, and how | AgentGov sees it stopped when |
|---|---|---|
| Copilot Studio | A Power Platform, AI or Global administrator quarantines it (Power Platform admin center, **Manage > Inventory**, or the Power Platform API); its owner can unpublish or delete it | The inventory reports it quarantined, or a whole-inventory import no longer lists it |
| Microsoft 365 | An AI or Global administrator blocks it in the Microsoft 365 admin center (**Agents**) | The catalog reports it blocked, or no longer lists it |
| Microsoft Entra Agent ID (an agent known only by its identity) | An administrator of its agent identity disables it in the Entra admin center | The identity is disabled (by an administrator or by Microsoft), or deleted |
| AWS, Google Cloud | Someone with rights over it in its account or project deletes it, or takes away who may call it | It is gone from a part read in full (permissions taken away don't show) |
| Salesforce | A Salesforce administrator deactivates it in Agentforce Builder | It has no active version, or is gone |
| Databricks | Someone who can manage it stops it (an app) or deletes it | The app's compute is stopped, or the agent is gone |
| Microsoft Foundry | Someone with rights over its project disables or deletes it | It is disabled, or gone |

An agent reported by two platforms is stopped where it runs: a Copilot Studio agent
published to Microsoft 365 counts as stopped once Copilot Studio quarantines it, since a
block in the Microsoft 365 admin center keeps it out of Microsoft 365 Copilot and Teams only.
Its issue says so when Microsoft 365 has it blocked and Copilot Studio still runs it.

Management rules don't block agents AgentGov can't stop: their issue says to stop the agent
in its platform instead ([management rules](management-rules.md)). The issue type can be
turned off, or given another severity, like any other ([kinds of
issues](issues.md#kinds-of-issues)).

## Acting as the signed-in admin

Some of Microsoft's admin APIs accept only a signed-in administrator: quarantining a
Copilot Studio agent, reading the Power Platform inventory and blocking a Microsoft 365
agent. When admins sign in to AgentGov through Microsoft Entra ID, AgentGov can call these
APIs as them, so they can act from AgentGov:

* **Quarantine** a Copilot Studio agent, or **Release from quarantine**, through the
  Power Platform API's [quarantine operations][quarantine]. A quarantined agent stops
  working in every channel, but its makers can still open and test it in Copilot Studio.
  Classic chatbots can't be quarantined.
* **Block in Microsoft 365** or **Unblock in Microsoft 365** an agent in the organisation's
  catalog, through Microsoft Graph's [package block API][package-block]. This API is in
  beta and needs a Microsoft Agent 365 licence, like the catalog sync.
* **Sync now** for the [Copilot Studio inventory](#copilot-studio-inventory).

The first two are on the agent's Copilot Studio or Microsoft 365 card. **Block** and
**Unblock** in the agent's toolbar also offer to do it in the platform in the same step.
If an agent is in both sources, AgentGov acts on the Copilot Studio agent, because
quarantine needs no Agent 365 licence. AgentGov makes its own change first. If AgentGov
refuses (for example, an unblock of an agent without a sponsor), the platform is left
alone. If the platform refuses, the agent stays blocked in AgentGov and AgentGov shows
Microsoft's error.

Microsoft checks the signed-in person's own rights: they need the AI administrator, Power
Platform administrator or Global administrator role in Entra ID. Microsoft records the
action under their name, and so does the ledger (`platform.agent_blocked`,
`platform.agent_unblocked`, `platform.imported`).

### Setting it up

1. In the Microsoft Entra admin center, register an application for signing in to
   AgentGov (**App registrations > New registration**, single tenant). Give it two
   **Web** redirect URIs: `<AGENTGOV_PUBLIC_URL>/auth/callback` for signing in and
   `<AGENTGOV_PUBLIC_URL>/ui/` for coming back after signing out. Under **Certificates &
   secrets**, create a client secret.
2. Under **App roles**, create the roles AgentGov maps: `agentgov-admin`,
   `agentgov-approver`, `agentgov-secops`, `agentgov-auditor`, `agentgov-registrar`, and
   `agentgov-person` for owners and sponsors who should see only what is sent to them (the
   value is what counts; or map the app roles you have with `AGENTGOV_OIDC_ROLE_MAP`). Then
   assign them to people under **Enterprise applications** > the app > **Users and
   groups** (assigning groups needs Entra ID P1 or P2), and set **Properties** >
   **Assignment required?** to **Yes**, so that nobody else can sign in ([who can sign
   in](administration.md#who-can-sign-in)). People without a role are turned away, unless
   the `issues` or `approvals-by-person` feature is on, which lets them sign in to see the
   issues sent to them and decide what agents acting for them ask.
3. Under **API permissions**, add these *delegated* permissions and grant admin consent:

   | API | Permission | For |
   |---|---|---|
   | Power Platform API | `CopilotStudio.AdminActions.Invoke` | Quarantine and release Copilot Studio agents |
   | Power Platform API | `ResourceQuery.Resources.Read` | Sync the Copilot Studio inventory |
   | Power Platform API | `EnvironmentManagement.Groups.Read` | [Push the connector allowlist](microsoft-connections.md#pushing-the-connector-allowlist-into-power-platform) to environment groups (optional) |
   | Microsoft Graph | `CopilotPackages.ReadWrite.All` | Block Microsoft 365 agents (optional; needs Agent 365) |
   | Microsoft Graph | `User.ReadBasic.All` | [Show who made each agent](#who-made-each-agent) by name (optional) |

   If **Power Platform API** isn't listed under **APIs my organization uses**, add it to
   the tenant first ([Microsoft's steps][pp-auth]):
   `az ad sp create --id 8578e004-a5c6-46e7-913e-12f58912df43`.
4. Give the control plane the app and turn the admin actions on. With Docker Compose, put
   them in `deploy/compose/.env` (on Kubernetes, see
   [Kubernetes](deploy/kubernetes.md#signing-in-with-microsoft-entra-id)):

   ```bash
   AGENTGOV_OIDC_ISSUER=https://login.microsoftonline.com/<tenant ID>/v2.0
   AGENTGOV_OIDC_CLIENT_ID=<application (client) ID>
   AGENTGOV_OIDC_CLIENT_SECRET=<client secret>
   AGENTGOV_MICROSOFT_ADMIN_ACTIONS=true
   ```

   Use the tenant ID (a GUID), not a domain name: Entra's tokens name the tenant by its
   ID, and AgentGov checks the issuer exactly. AgentGov works out Entra's endpoints from
   the issuer, reads roles from the app roles (`roles`), and asks for `offline_access`, so
   it gets a refresh token.

The same app registration can also run the [catalog sync](#microsoft-365-agent-catalog)
if you add the Graph *application* permission `CopilotPackages.Read.All` to it.

### How AgentGov holds the sign-in

When an admin signs in, AgentGov keeps the refresh token that Entra ID returns and swaps
it for short-lived access tokens to the Power Platform API or Graph when needed. The
refresh token is kept in the database for as long as the AgentGov session lasts
(`AGENTGOV_SESSION_HOURS`, 8 by default), so that every control-plane replica can act as
the admin, and a restart doesn't sign them out of Microsoft. It is sealed (AES-256-GCM)
with a key derived from the app's client secret and bound to its session, so the
database alone doesn't give it away; it never reaches the ledger, and it is useless
without the client secret anyway. Signing out, an admin ending the session on the
**Access** page, or the session running out deletes it. Access tokens stay in each
replica's memory until they expire.

A new client secret makes the sealed sign-ins unreadable: admins stay signed in to
AgentGov, but they need to sign in again to act in Microsoft, and AgentGov says so.

### From the CLI

`agentgov login` signs you in through Entra ID in your browser, and the CLI gets an
AgentGov session that can act in Microsoft too:

```bash
agentgov login
agentgov platforms sync copilot-studio
agentgov agents block sales-helper --in-platform --reason "Shares customer data"
agentgov agents platform-unblock sales-helper    # release it in Copilot Studio only
agentgov logout
```

See [Signing in](administration.md#signing-in) for how the CLI keeps its session.

## Doing it from the CLI or the API

| Task | Admin UI | CLI | API |
|---|---|---|---|
| See each source and its last sync | Platforms | `agentgov platforms status` | `GET /v1/platforms` |
| Sync the Microsoft 365 catalog | Platforms > **Sync now** | `agentgov platforms sync microsoft-365` | `POST /v1/platforms/microsoft-365/sync` |
| Sync every connection AgentGov's app may use | Platforms > Microsoft connections > **Sync all** | `agentgov platforms sync` | `POST /v1/platforms/sync` |
| Sync the Copilot Studio inventory, as you | Platforms > Copilot Studio > **Sync now** | `agentgov platforms sync copilot-studio` | `POST /v1/platforms/copilot-studio/sync` |
| Import the Copilot Studio inventory | Platforms > **Import inventory** | `agentgov platforms import FILE` | `POST /v1/platforms/copilot-studio/import` |
| Look up the people agents' platforms name | Platforms > Microsoft connections > Microsoft Entra users | `agentgov platforms sync entra-users` | `POST /v1/platforms/entra-users/sync` |
| Upload a list of users from Entra ID | Platforms > Copilot Studio > **Upload users** | `agentgov platforms import-users FILE` | `POST /v1/platforms/entra-users/import` (CSV or JSON) |
| Who made an agent, and whom adopting it suggests | Agent page > Owner and sponsors | `agentgov agents get REF` | `makers` and `suggested_owner` in `GET /v1/agents/{ref}` |
| Adopt agents at once | Agents > **Adopt n agents** | `agentgov agents adopt REF... \| --platform P --makers --owner TEAM` | `POST /v1/agents/adopt` |
| Quarantine or block an agent in its platform, as you | Agent > Copilot Studio or Microsoft 365 card, or **Block** / **Unblock** | `agentgov agents platform-block\|platform-unblock REF`, or `agentgov agents block\|unblock REF --in-platform` | `POST /v1/agents/{ref}/platform/block\|unblock` |
| The agents blocked in AgentGov that their platform still runs | Issues, or the agent's page (*Blocked in AgentGov only*) | `agentgov issues list --type platform.still_running` | `GET /v1/findings?type=platform.still_running`, or `still_runs_in` in `GET /v1/agents/{ref}` |
| List the agents from one platform | Platforms > *n agents* | `agentgov agents list --source platform:copilot-studio` | `GET /v1/agents?source=platform:copilot-studio` |
| See the connectors in use | Platforms > Connectors | `agentgov platforms connectors` | `GET /v1/platforms/connectors` |
| Approve a connector | Platforms > **Approve** | `agentgov platforms approve-connector shared_office365 --note "…"` | `PUT /v1/platforms/connectors/{id}/approval` |
| Remove an approval | Platforms > **Remove approval** | `agentgov platforms unapprove-connector shared_office365` | `DELETE /v1/platforms/connectors/{id}/approval` |
| Push the allowlist into Power Platform, as you | Platforms > Connectors > **Push to Power Platform** | `agentgov platforms connector-policy`, then `push-connector-policy --group ID` | `GET`/`POST /v1/platforms/connector-policy` |
| What a platform reports about one agent | Agent page | `agentgov agents get REF` | `platforms` in `GET /v1/agents/{ref}` |

Auditors and approvers can see everything here. Syncing, importing, changing the
allowlist and acting in a platform need an admin. Acting in a platform, syncing the
Copilot Studio inventory and pushing the allowlist into Power Platform also need an admin
who signed in through Entra ID: an API key can't do them.

[packages]: https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/api/admin-settings/package/copilotpackages-list
[inventory-schema]: https://learn.microsoft.com/en-us/microsoft-copilot-studio/admin-agent-inventory
[inventory-api]: https://learn.microsoft.com/en-us/power-platform/admin/inventory-api
[quarantine]: https://learn.microsoft.com/en-us/microsoft-copilot-studio/admin-api-quarantine
[package-block]: https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/api/admin-settings/package/copilotpackage-block
[pp-auth]: https://learn.microsoft.com/en-us/power-platform/admin/programmability-authentication-v2
