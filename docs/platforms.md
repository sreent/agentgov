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
  above, plus agents built elsewhere that have one, such as in Microsoft Foundry
  ([details](microsoft-connections.md#microsoft-entra-agent-id)).

Each agent becomes a registry agent with the source `platform:microsoft-365`,
`platform:copilot-studio` or `platform:entra-agent-id`. It starts as `discovered`, with an
"agent to review" finding. Adopt it to give it an owner, sponsors and periodic
attestation, like any other agent. AgentGov issues these agents no gateway credentials
and doesn't apply blueprints to them, because they never call the gateway. When more than
one source reports the same agent (a Copilot Studio agent published to Microsoft 365, and
its Entra agent identity), AgentGov matches them by Entra agent ID.

Agents built on AWS, Google Cloud, Salesforce and Databricks are read the same way, by
connectors of AgentGov's own ([other platforms](other-platforms.md)).

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
can only block an agent on behalf of an admin who signed in. With [Copilot Studio threat
detection](microsoft-connections.md#copilot-studio-threat-detection) enforcing, blocking a
Copilot Studio agent in AgentGov also stops its tool calls, because Copilot Studio asks
AgentGov before each one.

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
* **More than 1,000 agents.** Export them in pages with `--skip-token` and import each
  file. Importing is idempotent: agents already in the registry are updated.
* **Other ways to export.** The same rows come from the [Power Platform inventory
  API][inventory-api] (`POST https://api.powerplatform.com/resourcequery/resources/query`)
  and from `pac resource-query query-resources`. AgentGov accepts either a JSON list of
  rows or an object with a `data` list.

Sync or import again whenever you want AgentGov to catch up, for example after each
review. AgentGov can't do it on a schedule, because Microsoft needs a signed-in person.
Agents missing from an import are left as they were, because an export may cover only
some environments.

## Checks

AgentGov checks every imported Copilot Studio agent and raises a finding for each
problem it finds. A finding resolves itself when a later import shows the problem fixed.
Open findings also count towards the agent's risk score, so a risky agent also gets a
high-risk alert. Dismissing a finding (an accepted risk) takes it out of the score.

| Finding | Severity | Raised when the agent | Risk points |
|---|---|---|---|
| `platform.unapproved_connector` | High | uses a connector that isn't on the allowlist (only once the allowlist has a connector) | 20 |
| `platform.no_authentication` | High | is published with authentication set to *None*, so anyone who can reach a channel can use it | 25 |
| `platform.maker_credentials` | Medium | has tools that use its maker's connection, so every user reaches data with the maker's access | 10 |
| `platform.shared_with_everyone` | Medium | is shared with the whole organisation | 10 |

An agent that is simply waiting for review scores 15 points for it. That is less than a
shadow agent seen calling tools (30 points), because the platform already knows about
it.

## Connector allowlist

The **Connectors** table on the Platforms page lists every Power Platform connector
that Copilot Studio agents use. For each connector it shows:

* the agents that use it;
* the operations they call;
* how many of those operations run with the maker's connection;
* whether the connector is approved.

Approve the connectors your organisation allows, with a note on why. Until the first
connector is approved, nothing is flagged. After that, every agent that uses a connector
not on the list gets a `platform.unapproved_connector` finding. Approving or removing a
connector is recorded in the ledger and takes effect at once.

On its own, the allowlist reports; it does not enforce. Two optional connections make it
enforce:

* **Push to Power Platform** (`agentgov platforms push-connector-policy`) makes Power
  Platform block every other connector, as an [advanced connector
  policy](microsoft-connections.md#pushing-the-connector-allowlist-into-power-platform)
  on the environments an admin picks. It applies to apps and flows as well as agents, so
  AgentGov shows what it would do first.
* [Copilot Studio threat
  detection](microsoft-connections.md#copilot-studio-threat-detection) blocks a tool call
  that uses a connector not on the list, when Copilot Studio names the connector.

Without either, use Power Platform data policies (DLP) and keep them consistent with the
allowlist.

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
   `agentgov-approver`, `agentgov-secops`, `agentgov-auditor` and `agentgov-registrar` (the
   value is what counts). Then assign them to people under **Enterprise applications** > the
   app > **Users and groups** (assigning groups needs Entra ID P1 or P2). People without a
   role are turned away, unless the `approvals-by-person` feature is on, which lets them sign
   in to decide what agents acting for them ask.
3. Under **API permissions**, add these *delegated* permissions and grant admin consent:

   | API | Permission | For |
   |---|---|---|
   | Power Platform API | `CopilotStudio.AdminActions.Invoke` | Quarantine and release Copilot Studio agents |
   | Power Platform API | `ResourceQuery.Resources.Read` | Sync the Copilot Studio inventory |
   | Power Platform API | `EnvironmentManagement.Groups.Read` | [Push the connector allowlist](microsoft-connections.md#pushing-the-connector-allowlist-into-power-platform) to environment groups (optional) |
   | Microsoft Graph | `CopilotPackages.ReadWrite.All` | Block Microsoft 365 agents (optional; needs Agent 365) |

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
   AGENTGOV_OIDC_ROLES_CLAIM=roles
   AGENTGOV_MICROSOFT_ADMIN_ACTIONS=true
   ```

   Use the tenant ID (a GUID), not a domain name: Entra's tokens name the tenant by its
   ID, and AgentGov checks the issuer exactly. AgentGov works out Entra's endpoints from
   the issuer and asks for `offline_access`, so it gets a refresh token.

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
| Quarantine or block an agent in its platform, as you | Agent > Copilot Studio or Microsoft 365 card, or **Block** / **Unblock** | `agentgov agents platform-block\|platform-unblock REF`, or `agentgov agents block\|unblock REF --in-platform` | `POST /v1/agents/{ref}/platform/block\|unblock` |
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
