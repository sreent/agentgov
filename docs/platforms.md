# Agents on Microsoft 365 and Copilot Studio

In an organisation that uses Microsoft 365, most agents don't call tools through
AgentGov's gateway. People build them in Copilot Studio or Agent Builder, or install
them from partners, and they run inside Microsoft 365. AgentGov can't sit in front of
these agents, but it can govern what Microsoft reports about them. The **Platforms**
page (and `agentgov platforms`) brings two sources into the registry:

* the organisation's **Microsoft 365 agent catalog**, synced from Microsoft Graph;
* the **Copilot Studio inventory**: Copilot Studio and Agent Builder agents, imported
  from the Power Platform inventory together with the connectors each one uses.

Each agent becomes a registry agent with the source `platform:microsoft-365` or
`platform:copilot-studio`. It starts as `discovered`, with an "agent to review" finding.
Adopt it to give it an owner, sponsors and periodic attestation, like any other agent.
AgentGov issues these agents no gateway credentials and doesn't apply blueprints to them,
because they never call the gateway. When both sources report the same agent (a Copilot
Studio agent published to Microsoft 365), AgentGov matches them by Entra agent ID when
both carry one.

**AgentGov reads these platforms; it does not change them.** Blocking or deleting one of
these agents in AgentGov records the decision in the registry and the ledger, but the
agent keeps running. Block it in the Microsoft 365 admin center (**Agents**) or the
Power Platform admin center (**Manage > Inventory**) as well. Microsoft's API for
blocking agents accepts only a signed-in administrator and is in preview, so AgentGov
doesn't call it.

## Microsoft 365 agent catalog

AgentGov reads the catalog through the Microsoft Graph [Package Management
API][packages], as an application, so nobody needs to be signed in. It lists the
packages that Microsoft 365 Copilot can host
(`GET /v1.0/copilot/admin/catalog/packages?$filter=supportedHosts/any(h:h eq 'Copilot')`).
Microsoft requires a Microsoft Agent 365 licence for this API.

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
time with **Sync now** or `agentgov platforms sync`. A failed sync is shown on the
Platforms page with Microsoft's error.

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
signed-in person query it (an application gets HTTP 403), so an administrator exports
it and imports the file:

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

Import again whenever you want AgentGov to catch up, for example after each review.
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

The allowlist reports; it does not enforce. To stop makers from using a connector,
use Power Platform data policies (DLP) and keep them consistent with the allowlist.

## Doing it from the CLI or the API

| Task | Admin UI | CLI | API |
|---|---|---|---|
| See each source and its last sync | Platforms | `agentgov platforms status` | `GET /v1/platforms` |
| Sync the Microsoft 365 catalog | Platforms > **Sync now** | `agentgov platforms sync` | `POST /v1/platforms/microsoft-365/sync` |
| Import the Copilot Studio inventory | Platforms > **Import inventory** | `agentgov platforms import FILE` | `POST /v1/platforms/copilot-studio/import` |
| List the agents from one platform | Platforms > *n agents* | `agentgov agents list --source platform:copilot-studio` | `GET /v1/agents?source=platform:copilot-studio` |
| See the connectors in use | Platforms > Connectors | `agentgov platforms connectors` | `GET /v1/platforms/connectors` |
| Approve a connector | Platforms > **Approve** | `agentgov platforms approve-connector shared_office365 --note "…"` | `PUT /v1/platforms/connectors/{id}/approval` |
| Remove an approval | Platforms > **Remove approval** | `agentgov platforms unapprove-connector shared_office365` | `DELETE /v1/platforms/connectors/{id}/approval` |
| What a platform reports about one agent | Agent page | `agentgov agents get REF` | `platforms` in `GET /v1/agents/{ref}` |

Auditors and approvers can see everything here. Syncing, importing and changing the
allowlist need an admin.

[packages]: https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/api/admin-settings/package/copilotpackages-list
[inventory-schema]: https://learn.microsoft.com/en-us/microsoft-copilot-studio/admin-agent-inventory
[inventory-api]: https://learn.microsoft.com/en-us/power-platform/admin/power-platform-inventory#programmatic-access
