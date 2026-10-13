# Administering AgentGov

AgentGov has three ways in: the admin UI, the `agentgov` CLI and the HTTP API. They are
one application, not three. The UI and the CLI are both clients of the same API, so
every task below goes through the same endpoint, the same role check and the same
validation whichever way you do it. Every change is also recorded in the
[evidence ledger](architecture.md) under the name of whoever made it, as
`<role>:<name>` (for example `admin:alice@example.com` or `registrar:ci-pipeline`).

## Signing in

| | How |
|---|---|
| Admin UI | `<control plane>/ui`. Sign in with single sign-on, or paste an API token |
| CLI | Set `AGENTGOV_URL` (default `http://localhost:8000`), then run `agentgov login` to sign in with single sign-on, or set `AGENTGOV_TOKEN` to an API key or the bootstrap token. `agentgov whoami` shows who you are |
| API | `Authorization: Bearer <token>`. The interactive reference is at `<control plane>/docs` |

Create API keys on the UI's **Access** page or with `agentgov apikeys create`. The key is
shown once; only a hash is stored. Keep the bootstrap token (`AGENTGOV_ADMIN_TOKEN`)
for setup and emergencies.

`agentgov login` opens your browser at the identity provider. After you sign in, the
browser goes back to the CLI, which listens on a loopback address (`127.0.0.1`) for this
one sign-in. The CLI proves with PKCE that it started the sign-in and gets an AgentGov
session of its own, which lasts as long as one in the UI (`AGENTGOV_SESSION_HOURS`). The
session is saved for `AGENTGOV_URL` in `sessions.json` in the agentgov config directory
(`~/.config/agentgov` on Linux; set `AGENTGOV_CONFIG_DIR` to move it), readable only by
you. `agentgov logout` ends it. `AGENTGOV_TOKEN` (or `AGENTGOV_ADMIN_TOKEN`) takes
precedence over a saved session.
The session appears on the **Access** page like any other, and the ledger's
`admin.login` entry says it came from the CLI.

To sign in on a machine you reach over SSH, forward a port and fix the CLI to it:
`ssh -L 8765:127.0.0.1:8765 HOST`, then `agentgov login --no-browser --port 8765` on that
machine, and open the link it prints in your local browser. For scripts and CI
pipelines, use an API key instead.

### Signing out everywhere

When your session at the identity provider ends (you sign out there or in another app
that signs you in there, or its administrators end it or disable your account), the
provider can tell AgentGov, and your AgentGov sessions from it end too, in the UI and the
CLI, rather than when they would have expired. This is OpenID Connect Back-Channel
Logout: the provider posts a logout token it signed to
`<control plane>/auth/backchannel-logout`, and AgentGov checks that it comes from the
provider, for its client, and names your provider session or you. Each session it ends is
an `admin.logout` entry in the ledger, from the identity provider.

The Keycloak that comes with Compose and the chart is set up for it
(`AGENTGOV_BACKCHANNEL_LOGOUT_URL` on Keycloak, read as it first imports the realm). For
a realm made before, or another provider, set the client's back-channel logout URL to the
address above, as the provider reaches the control plane, and ask for the session ID in
logout tokens (Keycloak: the `agentgov-admin` client's **Backchannel logout URL** and
**Backchannel logout session required**). A provider that can't do this leaves sessions
to end at expiry (`AGENTGOV_SESSION_HOURS`), or when you sign them out on the **Access**
page.

### Your identity provider

Single sign-on is for people: administrators, approvers, the security team, auditors, and
the owners and others who sign in to see the issues and approval requests sent to them.
Agents never use it; they authenticate at the gateway with identities of their own
([agents' own identities](agent-identity.md)).

The Keycloak that comes with Compose and the chart signs people in, and can bring in your
directory ([signing in](deploy/local.md#signing-in)). Any OpenID Connect provider can
sign them in instead:

1. Register AgentGov with the provider as a web application (a confidential client),
   with the redirect URI `<AGENTGOV_PUBLIC_URL>/auth/callback` and, where it asks, the
   sign-out redirect `<AGENTGOV_PUBLIC_URL>/ui/` and the back-channel logout URL
   `<AGENTGOV_PUBLIC_URL>/auth/backchannel-logout`. AgentGov signs in with the
   authorization code flow and PKCE, and keeps sessions on the server.
2. Set `AGENTGOV_OIDC_ISSUER` to the provider's issuer, `AGENTGOV_OIDC_CLIENT_ID` and
   `AGENTGOV_OIDC_CLIENT_SECRET` to the application's. AgentGov reads the provider's
   endpoints from its discovery document (`<issuer>/.well-known/openid-configuration`),
   when it first needs them and again every hour; while the provider can't be read, the
   **Access** page says so, and sign-ins fail with a message saying the provider didn't
   answer. It proves itself with the client secret in the way the provider takes
   (`AGENTGOV_OIDC_CLIENT_AUTH` to choose).
3. Say where roles come from. The ID token's `groups` claim, by default (Keycloak's
   realm roles, and Microsoft Entra ID's app roles, are read where those put them), names
   the person's groups; a group called `agentgov-admin` makes them an admin, and so on for
   the other roles. To use the groups you have, map them instead:
   `AGENTGOV_OIDC_ROLE_MAP=<group ID or name>=admin,Security Operations=secops`, and then
   only the values mapped give roles. `AGENTGOV_OIDC_ROLES_CLAIM` names other claims. The
   **Access** page shows how AgentGov reads the provider.
4. Where the provider's tokens carry no groups, give roles in AgentGov
   ([below](#roles-given-in-agentgov)); give the first administrators theirs there, too.

| Provider | Issuer | Roles |
|---|---|---|
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant ID>/v2.0` | App roles, assigned to people and groups ([setting it up](platforms.md#setting-it-up), which also lets AgentGov act in Microsoft 365 as the person signed in) |
| Okta | `https://<org>.okta.com`, or a custom authorization server's (`https://<org>.okta.com/oauth2/default`) | A groups claim added to the ID token, on the application's sign-on settings or the authorization server |
| Google Workspace | `https://accounts.google.com` | None in Google's tokens: [give roles in AgentGov](#roles-given-in-agentgov). `AGENTGOV_OIDC_ALLOWED_DOMAINS` is required, because every Google account shares this issuer |
| Ping Identity | PingOne: `https://auth.pingone.com/<environment ID>/as` | A groups claim added to the ID token |
| OneLogin | `https://<subdomain>.onelogin.com/oidc/2` | A groups claim added to the ID token |
| JumpCloud | `https://oauth.id.jumpcloud.com/` | A groups claim added to the ID token |
| Auth0 | `https://<tenant>.auth0.com/` | A claim an Action adds to the ID token, with a namespaced name such as `https://agentgov/roles`, set as `AGENTGOV_OIDC_ROLES_CLAIM` |
| Amazon Cognito | `https://cognito-idp.<region>.amazonaws.com/<user pool ID>` | `cognito:groups`, set as `AGENTGOV_OIDC_ROLES_CLAIM` |
| Another Keycloak | `https://<host>/realms/<realm>` | Realm roles, as with the bundled one |

Write the issuer as the provider's tokens name it; a trailing slash may be left off.
`AGENTGOV_OIDC_ALLOWED_DOMAINS` (comma-separated) lets in only people whose email address
the provider vouches for is in one of those domains, and with Google, only accounts of
your organisation (its hosted domain). A person's name in AgentGov is that email address,
which issues and approvals are addressed to; Microsoft Entra ID's people are named by their
email address or else their user principal name. Some providers, Google among them, have
no sign-out endpoint: signing out then ends the AgentGov session, not the provider's.

A provider that only speaks SAML, or a directory (Active Directory, LDAP), signs people in
through Keycloak, which brokers it: connect it to the realm as an identity provider or
through user federation.

### Roles given in AgentGov

An administrator can give a person a role in AgentGov itself, on the **Access** page or
with `agentgov access grant alice@example.com auditor --reason "..."`: for providers
whose tokens carry no groups, such as Google's, and for the first administrators before
groups are set up. It applies from the person's next sign-in with that email address, the
one the provider vouches for, beside the roles the provider gives them. Taking it away
(`agentgov access revoke`) ends their sessions at once. Both are in the ledger
(`access.role_granted`, `access.role_revoked`), and each sign-in's `admin.login` entry
lists the roles given here.

## Start here

A new AgentGov starts with a question on its **Overview**: where are your agents? Copilot
Studio, Microsoft 365 Copilot agents, Microsoft Entra Agent ID, AWS, Google Cloud,
Salesforce, Databricks, Microsoft Foundry, or your own agents, through AgentGov's gateway.
AgentGov turns on what reads the places chosen and turns off what reads the others (but
what the deployment pins), and starts from the [inventory starting
point](features.md#starting-points), or from the monitor one when agents will call through
its gateway. Choosing again later changes them again.

A checklist then leads to a first useful day, each step worked out from the registry:

1. **Say where your agents are**, as above.
2. **Find your agents**: how, for each place chosen, such as importing Copilot Studio's
   inventory ([platforms](platforms.md#copilot-studio-inventory)).
3. **Name a catch-all team**, for the issues no agent's owner, sponsor or team takes
   ([issues](issues.md)). Until there is one, the `issues` feature says it is limited.
4. **Review the agents found**: adopt the ones you keep, and block or delete the others
   where they run.
5. **Give every agent an owner**.

It stays on the Overview until every step is done, or an administrator hides it. With the
CLI, `agentgov start` shows it, `agentgov start --place copilot-studio --place aws`
answers, and `--hide` hides it; with the API, `GET` and `PUT /v1/start`
(`{"places": [...]}` or `{"hidden": true}`). The answer is in the ledger
(`start.answered`), with the starting point and the features it changed.

## Roles

| Role | Can |
|---|---|
| `admin` | Everything below, plus agent lifecycle, blueprints, access packages, [management rules](management-rules.md), tool servers, model providers, identity issuers, policies, credentials, API keys, platform syncs, the connector allowlist, destinations (SIEMs, chats and [service desks](tickets.md)), teams and which [features](features.md) are used |
| `approver` | Read everything; decide approval requests and requests for [access packages](access-packages.md); acknowledge, resolve, dismiss and reopen [issues](issues.md) and accept their risks, but not those of agents they are accountable for; attest the agents it sponsors; classify agents for the [classification register](evidence.md#a-classification-register) |
| `secops` | The security team's tools and analysts: read everything, and, as far as the hand-off to [security operations](secops.md) allows, acknowledge, resolve, dismiss and reopen issues and accept their risks (triage), block and unblock agents, tool servers, model providers and identity issuers (contain), and decide the approval requests sent to approvers (decide) |
| `auditor` | Read everything, including the ledger and the list of API keys; change nothing. They start on **Compliance** |
| `registrar` | Register agents and tool servers, which wait for an admin's review (for CI pipelines and developers), ask for [access packages](access-packages.md) for agents, and report the MCP servers set up on developers' machines; it cannot read the registry |
| `person` | Someone without an AgentGov role, signed in to see and acknowledge the [issues](issues.md) sent to them while the `issues` feature is on, to ask for and review the access packages of the agents they own or sponsor, and to decide the approval requests that agents acting for them sent them while `approvals-by-person` is on ([acting for people](acting-for-people.md)), and to attest the agents they sponsor; sees nothing else |
| `service` | The internal endpoints used by OPA, the governance processor, the gateway's config sidecar and the OpenTelemetry Collector; with mutual TLS between the components, only on the control plane's internal port ([production](production.md#mutual-tls-between-components)) |

People who sign in with single sign-on get their roles from the identity provider each time
they sign in ([your identity provider](#your-identity-provider), and the demo realm's users
in [signing in](deploy/local.md#signing-in)), and from the [roles given in
AgentGov](#roles-given-in-agentgov). To take someone's access away, remove their role
there, then sign them out on the **Access** page so that their open sessions end too. The same page lists everyone who has signed
in (or been refused) and every API key, for access reviews. API keys have one role each.
The UI only shows the controls a role may use; the API enforces the roles either way.

## The menu

The admin center's menu has the overview first, then five groups:

| Group | Pages | For |
|---|---|---|
| *Work* | **Approvals**, **Issues** | What waits for someone: decisions ([below](#approvals)), and issues to take on |
| *Agents* | **Agents**, **Agent map**, **Platforms** | What there is: the registry, which agents call which, and the platforms agents come from |
| *Gateway* | **Tool servers**, **Models**, **Policies**, **Developer tools** | What agents' calls through the gateway may reach, and the rules for them: unused [without the gateway](deploy/local.md#just-the-inventory) |
| *Evidence* | **Ledger**, **Compliance**, **Register** | What happened, the reports for a framework, and how each agent is classified |
| *Settings* | **Teams**, **Security operations**, **Access**, **Features** | Who takes the issues, the security team's tools, who signs in, and which features are on |

People without an AgentGov role see only their issues and the approvals waiting for them.

## Approvals

**Approvals** gathers everything waiting for a decision, each kind for those who may make
it, and its badge counts them:

| Kind | Who decides | Where |
|---|---|---|
| Calls policy held for a person, such as a tool its server marks destructive | Approvers and administrators, the security team from the hand-off's *decide* level, or the person they were sent to ([acting for people](acting-for-people.md#approvals-sent-to-the-person)) | On the page: **Approve**, **Deny** |
| Access packages asked for agents | Approvers and administrators, but not whoever asked ([access packages](access-packages.md)) | On the page |
| Risks the people an issue reached ask to be accepted | Approvers and administrators, and the security team from *triage* on; nobody accountable for the agent | On the issue: **Accept the risk**, **Decline** ([issues](issues.md)) |
| Agents and tool servers registered for review | Administrators | On the page: **Approve**, **Block** |
| Tool definitions that changed since they were approved | Administrators | In the tool server's catalog: **Approve new definition** |
| Agents found on platforms that nobody has reviewed | Administrators | **Agents**, not reviewed yet: **Adopt** |

The same list is `agentgov inbox`, with the command that decides each kind, and
`GET /v1/inbox`.

## Tasks

| Task | Admin UI | CLI | API |
|---|---|---|---|
| Register an agent | Agents → **Register agent** | `agentgov agents create NAME --blueprint B --sponsor S [--approve]` | `POST /v1/agents` |
| Edit an agent | Agent → **Edit** | `agentgov agents update REF --owner …` | `PATCH /v1/agents/{ref}` |
| Edit only if nobody changed it since you looked ([production](production.md#people-working-at-once)) | Every **Edit** form does | `agentgov <kind> update ... --if-version N` | `If-Match: "N"` on `PATCH` (`PUT` for policies); 412 if it changed |
| See the control plane's replicas and which one leads | Overview → *Control plane* | `agentgov replicas` | `GET /v1/replicas` |
| Approve, block, unblock, delete, restore | Agent toolbar | `agentgov agents approve\|block\|unblock\|delete\|restore REF` | `POST /v1/agents/{ref}/{action}` |
| Sort and filter the agents, and download those shown as a spreadsheet | Agents → a column's header; *Where*, *Risk*, *Owner*; **Download CSV** | `agentgov agents list --source S --risk R --csv` (`-q`: only their names) | `GET /v1/agents?source=&risk_level=` |
| Approve, block, unblock, delete or restore many agents at once ([many agents at once](#many-agents-at-once)) | Agents → tick them → **Approve**, **Block**, … | `agentgov agents approve\|block\|unblock\|delete\|restore REF REF ...` | `POST /v1/agents/bulk` |
| Change the owner, team, sponsors or blueprint of many agents at once | Agents → tick them → **Edit…** | `agentgov agents update REF REF ... --owner T --add-sponsor P --remove-sponsor P` | `POST /v1/agents/bulk`, `action: update` |
| Adopt an unmanaged agent | Agent → **Adopt** | `agentgov agents lifecycle REF adopt` | `POST /v1/agents/{ref}/adopt` |
| Adopt agents at once, with their makers as owners | Agents → **Adopt n agents** | `agentgov agents adopt --platform copilot-studio --makers` | `POST /v1/agents/adopt` |
| Delete a deleted agent permanently (otherwise it is purged after `AGENTGOV_SOFT_DELETE_RETENTION_DAYS`, 30 by default) | Agent → **Delete permanently** | `agentgov agents purge REF` | `DELETE /v1/agents/{ref}` |
| Attest an agent: its sponsors, whatever their role, and administrators | Agent → **Attest**, or **Attest** on the issue that its review is due | `agentgov agents attest REF` | `POST /v1/agents/{ref}/attest` |
| Show or rotate an agent's client secret | Agent → Identity → **Show secret** / **Rotate** | `agentgov agents credentials REF [--rotate]` | `POST /v1/agents/{ref}/credentials` |
| Approve, edit, block, delete identity issuers ([agents' own identities](agent-identity.md)) | Access → *Agent identity issuers* → **Add issuer**, **Edit**, **Block**/**Unblock**, **Delete** | `agentgov issuers create\|update\|block\|unblock\|delete` | `POST /v1/identity-issuers`, `PATCH`/`DELETE /v1/identity-issuers/{name}`, `POST /v1/identity-issuers/{name}/block\|unblock` |
| Give an agent its own identity instead of a client secret | Agent → **Edit** → *Authentication* | `agentgov agents update REF --workload-identity ISSUER:SUBJECT` (`--no-workload-identity` to go back) | `workload_identity` in `PATCH /v1/agents/{ref}` |
| See how an agent with its own identity authenticates | Agent → Identity → **How it authenticates** | `agentgov agents credentials REF` | `POST /v1/agents/{ref}/credentials` |
| Make an agent one people sign in to, such as developers' MCP clients (a public client) | Agent → **Edit** → *Authentication*, *Its tokens are for* | `agentgov agents update REF --client-type public [--redirect-uri URI]` | `client_type`, `redirect_uris` in `PATCH /v1/agents/{ref}` |
| See where people sign in to a public client | Agent → Identity → **How people sign in**; **Developer tools** | `agentgov agents credentials REF` | `POST /v1/agents/{ref}/credentials` |
| Have agents reach a server outside the gateway with identity assertions | Tool servers → **Edit** → *Outside the gateway* | `agentgov toolservers update S --no-gateway --authorization-server URL [--oauth-client-id ID]` | `authorization_server`, `oauth_client_id` in `PATCH /v1/toolservers/{name}`; agents ask `POST /oauth2/token` |
| See or recompute risk | Agent → Risk → **Recalculate** | `agentgov agents risk REF [--refresh]` | `GET /v1/agents/{ref}/risk`, `POST /v1/agents/{ref}/risk/refresh` |
| Create, edit, delete blueprints | Policies → **New blueprint**, **Edit**, **Delete** | `agentgov blueprints create\|update\|delete` | `POST /v1/blueprints`, `PATCH`/`DELETE /v1/blueprints/{name}` |
| Register, edit, delete tool servers | Tool servers → **Register tool server**, **Edit**, **Delete** | `agentgov toolservers create\|update\|delete` | `POST /v1/toolservers`, `PATCH`/`DELETE /v1/toolservers/{name}` |
| Approve, block, unblock a tool server | Tool servers → **Approve**, **Block server**, **Unblock** | `agentgov toolservers approve\|block\|unblock NAME` | `POST /v1/toolservers/{name}/{action}` |
| Accept a changed tool definition | Tool catalog → **Approve new definition** | `agentgov toolservers approve-tool NAME TOOL` | `POST /v1/toolservers/{name}/tools/{tool}/approve` |
| List a tool server for developers, or register one only for developers ([developer tools](developer-tools.md)) | Tool servers → **Edit** / **Register tool server** → *Who uses it* | `agentgov toolservers update crm --developers`, `agentgov toolservers create NAME --no-gateway --developers --package npm:PKG@VERSION` | `developers`, `gateway`, `packages` in `POST`/`PATCH /v1/toolservers` |
| See the MCP registry and its address for GitHub Copilot | Developer tools | `agentgov mcp registry` | `GET /v1/mcp/registry`; the registry itself at `/registry/v0.1/servers` |
| Get the managed-settings.json allowlist | Developer tools → **managed-settings.json** | `agentgov mcp managed-settings -o managed-settings.json` | `GET /v1/mcp/managed-settings` |
| Report the MCP servers on a machine | — | `agentgov mcp scan --report` | `POST /v1/mcp/sightings` |
| See the MCP servers developers set up | Developer tools → *Set up on developers' machines* | `agentgov mcp sightings` | `GET /v1/mcp/sightings` |
| Approve, edit, delete model providers ([model calls](models.md)) | Models → **Add provider**, **Edit**, **Delete** | `agentgov models create\|update\|delete` | `POST /v1/models/providers`, `PATCH`/`DELETE /v1/models/providers/{ref}` |
| Block or unblock a model provider | Models → **Block**, **Unblock** | `agentgov models block\|unblock NAME` | `POST /v1/models/providers/{ref}/block\|unblock` |
| Give a blueprint or an agent models, and a daily token budget | Blueprint or agent → **Edit** → Models | `agentgov blueprints update B --model-access 'openai:gpt-4.1*' --token-budget N` (agents: the same options) | `model_access`, `daily_token_budget` in `PATCH /v1/blueprints/{name}` or `PATCH /v1/agents/{ref}` |
| See model usage, cost and budgets, and who is spending | Models; an agent's page → Models | `agentgov models usage [--agent A] [--days N] [--by owner\|sponsor]` | `GET /v1/models/usage` |
| Add, edit, enable, disable, delete policies | Policies → **Add policy**, **Edit**, **Disable**/**Enable**, **Delete** | `agentgov policies create\|update\|enable\|disable\|delete` | `POST /v1/policies`, `PUT`/`DELETE /v1/policies/{name}` |
| Say whom a blueprint's agents act for, and who decides their approvals for a person ([acting for people](acting-for-people.md)) | Blueprint → **Edit** → People | `agentgov blueprints update B --acts-for people --people-groups support --approvals-by person` | `acts_for`, `people_groups`, `approvals_by` in `PATCH /v1/blueprints/{name}` |
| Publish an agent that serves A2A on the gateway ([agent to agent](agent-to-agent.md)) | Agent → **Edit** → *Agent to agent* → *A2A endpoint* | `agentgov agents update REF --a2a-url URL` (`--no-a2a` to stop) | `a2a_url` in `PATCH /v1/agents/{ref}` |
| Say what stops calls to it that go around the gateway ([calls around the gateway](agent-to-agent.md#calls-around-the-gateway)) | Agent → **Edit** → *Agent to agent* → *Calls around the gateway are stopped by* | `agentgov agents update REF --a2a-protection network` or `delegation` (`--no-a2a-protection` for neither) | `a2a_protection` in `PATCH /v1/agents/{ref}` |
| Say which agents a blueprint's agents, or one agent, may call | Blueprint → **Edit** → *Agent to agent*; agent → **Edit** → *Extra agents it may call* | `agentgov blueprints update B --agent-access billing-agent` (agents: the same option; `--no-agent-access` to clear) | `agent_access` in `PATCH /v1/blueprints/{name}` or `PATCH /v1/agents/{ref}` |
| See where agents call an agent, whom it may call and who may call it | Agent → *Agent to agent*; **Agent map** | `agentgov agents a2a REF` | `GET /v1/agents/{ref}/a2a`, `GET /v1/graph` |
| Require a blueprint's agents to authenticate with their own identity, never a client secret | Blueprint → **Edit** → *Require a workload identity* | `agentgov blueprints update B --require-workload-identity` (`--allow-secrets` to stop) | `require_workload_identity` in `PATCH /v1/blueprints/{name}` |
| Ask what policy would decide, for a tool call, a model call or a call to another agent | Policies → **What if** | `agentgov policies evaluate --server crm --tool delete_customer --agent support-bot`, or `--provider openai --model gpt-4.1`, or `--call-agent billing-agent`; `--user sam --groups support` for a call for a person | `POST /v1/policies/evaluate` |
| Apply manifests | Policies → **Import manifests** | `agentgov apply -f DIR` | `POST /v1/apply` |
| Export manifests | Policies → **Export manifests** | `agentgov export` | `GET /v1/export` |
| Decide an approval request | Approvals → **Approve** / **Deny** | `agentgov approvals approve\|deny ID` | `POST /v1/approvals/{id}/approve\|deny` |
| See the approval requests sent to you, as the person an agent acted for | Approvals → *Waiting for you* | `agentgov approvals list --mine` | `GET /v1/me/approvals` |
| Resolve, dismiss, reopen issues | Issues | `agentgov issues resolve\|reopen ID`, `agentgov issues dismiss ID --reason R [--until DATE]` | `POST /v1/findings/{id}/resolve\|dismiss\|reopen` |
| Do one of those to many issues at once, or acknowledge them or accept their risk ([issues](issues.md#many-at-once)) | Issues → tick them, or *Group by agent* and tick an agent | `agentgov issues acknowledge\|resolve\|dismiss\|accept\|reopen ID ID ...` | `POST /v1/findings/bulk` |
| Download the issues shown as a spreadsheet | Issues → **Download CSV** | `agentgov issues list --csv` (`-q`: only their IDs) | `GET /v1/findings` |
| See who an issue is with, its messages and its history ([issues](issues.md)) | Issues → **Details** | `agentgov issues get ID` | `GET /v1/findings/{id}` |
| See the issues sent to you, as an owner, a sponsor or a team member | Issues → *Yours* (people without a role: *Your issues*) | `agentgov issues list --mine` | `GET /v1/me/issues` |
| List issues, a page at a time, by type and severity | Issues: the type and severity filters, and **Show more** | `agentgov issues list --type T --severity S --limit N` | `GET /v1/findings?type=&severity=&limit=&offset=` (`X-Total-Count` says how many in all) |
| Acknowledge an issue, or accept its risk until a date | Issues → **Acknowledge**, **Accept risk** | `agentgov issues acknowledge ID`, `agentgov issues accept ID --reason R --until DATE` | `POST /v1/findings/{id}/acknowledge`, `POST /v1/findings/{id}/accept` |
| Add, edit and delete teams, and choose the default team | **Teams** | `agentgov teams create\|update\|delete`, `agentgov teams list` | `POST /v1/teams`, `PATCH`/`DELETE /v1/teams/{name}` |
| Add, edit and delete access packages ([access packages](access-packages.md)) | Policies → *Access packages* | `agentgov access-packages create\|update\|delete`, `agentgov access-packages list` | `POST /v1/access-packages`, `PATCH`/`DELETE /v1/access-packages/{name}` |
| Ask for an access package for an agent, or renew one | Agent → *Access packages* → **Request access**, **Renew** | `agentgov access-packages request AGENT PACKAGE --reason R` | `POST /v1/access-assignments` |
| Decide, revoke or review an agent's access package | Approvals → *Access requests*; agent → *Access packages* | `agentgov access-packages approve\|deny\|revoke ID`, `agentgov access-packages review ID --keep\|--remove` | `POST /v1/access-assignments/{id}/approve\|deny\|revoke\|review` |
| Add, edit, preview and delete management rules, and run them now ([management rules](management-rules.md)) | Policies → *Management rules* → **New rule**, **Preview**, **Edit**, **Delete**, **Run now** | `agentgov rules create\|update\|delete\|preview\|evaluate`, `agentgov rules list` | `POST /v1/rules`, `PATCH`/`DELETE /v1/rules/{name}`, `GET /v1/rules/{name}/preview`, `POST /v1/rules/preview`, `POST /v1/rules/evaluate` |
| See the management rules an agent matches, and what each will do | Agent → *Management rules* | `agentgov rules agent AGENT` | `GET /v1/agents/{ref}/rules` |
| Name the team issues about an agent escalate to | Blueprint or agent → **Edit** → *Team* | `agentgov blueprints update B --team T` (agents: the same option) | `team` in `PATCH /v1/blueprints/{name}` or `PATCH /v1/agents/{ref}` |
| Browse, verify and export the ledger | Ledger → filters, **Verify chain**, **Export JSONL** | `agentgov ledger tail --agent A`, `ledger verify`, `ledger export` | `GET /v1/ledger`, `/v1/ledger/verify`, `/v1/ledger/export` |
| Check an export, the ledger's archives or an evidence pack offline, against the time-stamped checkpoints ([evidence](evidence.md)) | — | `agentgov ledger verify --file F [--file F ...] --checkpoints DIR`, `agentgov ledger verify --pack P` | — |
| Keep a checkpoint of the ledger, and get its time-stamp | Ledger → *Checkpoints and retention* → **Make a checkpoint**, **Time-stamp** | `agentgov ledger checkpoint`, `ledger checkpoints`, `ledger proof SEQ` | `POST`/`GET /v1/ledger/checkpoints`, `GET /v1/ledger/checkpoints/{seq}/timestamp` |
| See how long things are kept, and run retention now | Ledger → *Checkpoints and retention* | `agentgov ledger retention [--run]` | `GET /v1/ledger/retention`, `POST /v1/ledger/retention/run` |
| See whether the database lost ledger entries (a restore), and accept the restore ([backing up and restoring](backup.md)) | Ledger | `agentgov ledger witness`, `agentgov ledger accept-restore` | `GET /v1/ledger/witness`, `POST /v1/ledger/witness/accept` |
| Read a compliance report, and download the evidence pack | **Compliance** → **Evidence pack** | `agentgov evidence report --framework F`, `agentgov evidence pack -o FILE` | `GET /v1/evidence/report`, `GET /v1/evidence/pack` |
| Classify agents under the EU AI Act, one or many ([classification register](evidence.md#a-classification-register)) | Agent → *Classification* → **Classify**; **Register** → **Classify**; Agents → tick them → **Classify…** | `agentgov agents classify REF [REF ...] --category C --role R [--basis B] [--purpose P]` (`--clear` to undo) | `PUT`/`DELETE /v1/agents/{ref}/classification`; `POST /v1/agents/bulk`, `action: classify` |
| See the classification register, and download it as a spreadsheet | **Register** → **Download CSV** | `agentgov evidence register [--csv]` | `GET /v1/evidence/register` |
| See what agents did for a person | Ledger → *On behalf of* | `agentgov ledger tail --user sam` | `GET /v1/ledger?user=sam` |
| See the calls between agents, and the chain of agents behind any call | Ledger, type `decision.a2a.*`; an entry's *Chain* | `agentgov ledger tail --type 'decision.a2a.*'` | `GET /v1/ledger?type=decision.a2a.*` (`details.chain`) |
| Open the trace of a gateway decision | Ledger or an agent's Recent activity → **Open trace** | `agentgov ledger tail --traces` | `trace_url` on `GET /v1/ledger` entries (set `AGENTGOV_TRACE_URL`) |
| Create, review and revoke API keys | Access → **Create API key**, **Revoke** | `agentgov apikeys create\|list\|revoke` | `POST`/`GET /v1/apikeys`, `DELETE /v1/apikeys/{id}` |
| See who has signed in, with which roles | Access → People | `agentgov access list`, `agentgov access sessions` | `GET /v1/access` |
| Sign someone out | Access → People → **Sign out** | `agentgov access sign-out PERSON`, `agentgov access end-session ID` | `POST /v1/access/people/{subject}/sign-out`, `DELETE /v1/access/sessions/{id}` |
| See each Microsoft connection and how it is doing | Platforms → Microsoft connections | `agentgov platforms status` | `connections` in `GET /v1/platforms` |
| Sync every Microsoft connection AgentGov's app may use | Platforms → Microsoft connections → **Sync all** | `agentgov platforms sync` | `POST /v1/platforms/sync` |
| Sync one: the Microsoft 365 agent catalog, Entra Agent ID, the Purview audit log or Defender's alerts | Platforms → Microsoft connections → **Sync now** | `agentgov platforms sync microsoft-365\|entra-agent-id\|purview-audit\|defender` | `POST /v1/platforms/{connection}/sync` |
| Import Copilot Studio agents | Platforms → **Import inventory** | `agentgov platforms import FILE` | `POST /v1/platforms/copilot-studio/import` |
| Sync Copilot Studio agents as yourself (Entra ID sign-in) | Platforms → Copilot Studio → **Sync now** | `agentgov platforms sync copilot-studio` | `POST /v1/platforms/copilot-studio/sync` |
| Quarantine or block an agent in Copilot Studio or Microsoft 365 as yourself (Entra ID sign-in) | Agent → its platform card, or tick the box in **Block** / **Unblock** | `agentgov agents platform-block\|platform-unblock REF`, `agentgov agents block\|unblock REF --in-platform` | `POST /v1/agents/{ref}/platform/block\|unblock` |
| List agents from one platform | Platforms → *n agents* | `agentgov agents list --source platform:copilot-studio` | `GET /v1/agents?source=…` |
| See the connectors agents use; approve or remove one | Platforms → Connectors | `agentgov platforms connectors`, `approve-connector ID`, `unapprove-connector ID` | `GET /v1/platforms/connectors`, `PUT`/`DELETE /v1/platforms/connectors/{id}/approval` |
| Push the connector allowlist into Power Platform as yourself (Entra ID sign-in), after seeing what it would do | Platforms → Connectors → **Push to Power Platform** | `agentgov platforms connector-policy`, `agentgov platforms push-connector-policy --group ID` | `GET`/`POST /v1/platforms/connector-policy` |
| See what Copilot Studio threat detection decided | Platforms → Microsoft connections; Ledger, type `decision.copilot_studio` | `agentgov platforms status`, `agentgov ledger tail --type decision.copilot_studio` | `threat_detection` in `GET /v1/platforms`; `GET /v1/ledger?type=decision.copilot_studio` |
| See an agent's instructions and the problems in them | Agent → Instructions | `agentgov agents instructions REF` | `GET /v1/agents/{ref}/instructions` |
| Set, forget or rescan an agent's instructions | Agent → Instructions → **Add instructions** / **Edit**, **Forget**, **Rescan** | `agentgov agents set-instructions\|clear-instructions\|rescan-instructions REF` | `PUT`/`DELETE /v1/agents/{ref}/instructions`, `POST …/rescan` |
| Check instructions before deploying an agent | — | `agentgov instructions check FILE` | `POST /v1/instructions/check` |
| Choose which features are used, and how strictly ([features](features.md)) | Features | `agentgov features list`, `agentgov features set FEATURE MODE` | `GET /v1/features`, `PUT /v1/features/{feature}` |
| See whether each feature can do what its mode says, and what AgentGov can reach ([is it working?](features.md#is-it-working)) | Features | `agentgov features list`, `agentgov components` | `GET /v1/features`, `GET /v1/components` |
| Choose how much is handed to the security team ([security operations](secops.md)) | Security operations → *Hand-off* | `agentgov secops level LEVEL`, `agentgov secops status` | `PUT /v1/features/security-operations`, `GET /v1/secops` |
| Add, edit, test, pause, resume, replay and delete destinations (SIEMs, Teams, Slack) | Security operations → **Add destination**, **Test**, **Edit**, **Pause**/**Resume**, **Replay**, **Delete** | `agentgov destinations create\|update\|test\|pause\|resume\|replay\|delete` | `POST /v1/destinations`, `PATCH`/`DELETE /v1/destinations/{name}`, `POST /v1/destinations/{name}/{action}` |
| Read the ledger as OCSF events | Security operations → *Events API* | `agentgov secops events [--after N] [--follow]` | `GET /v1/secops/events?after=N` |
| Open issues as tickets in ServiceNow, Jira Service Management or Freshservice, kept in step ([tickets](tickets.md)) | Security operations → **Add destination** → a service desk; an issue's page → *Tickets* | `agentgov destinations create NAME --kind servicenow --url URL --group G`, `agentgov tickets list` | `POST /v1/destinations` with `kind` and `tickets`; `GET /v1/tickets` |
| See what monitored controls would have stopped | Ledger → decision **Monitored** | `agentgov ledger tail --decision monitored` | `GET /v1/ledger?decision=monitored` |

Two commands run where the control plane runs, against its database
(`AGENTGOV_DATABASE_URL`) rather than its API: `agentgov db status` shows the schema's
revision and the migrations pending, and `agentgov db upgrade` applies them (`--sql`
prints them instead). The control plane also applies them when it starts, unless
`AGENTGOV_DATABASE_AUTO_MIGRATE` is `false` (upgrading with [Compose](deploy/local.md#upgrading) or [Kubernetes](deploy/kubernetes.md#upgrading)).

Every CLI command has `--help`. Commands that cannot be undone (`purge`, `delete` of
blueprints, tool servers, model providers, identity issuers, destinations and policies,
`apikeys revoke`, `agents clear-instructions`), `destinations replay`,
`platforms push-connector-policy`, and `features set` (or `secops level`) when it lowers a
feature, ask for confirmation unless you pass `--yes`.

## Many agents at once

With a few hundred agents, reviews come in batches: the agents someone who left owned, those
found on a platform, the riskiest. On the **Agents** page, a column's header sorts by it (the
riskiest or the most recently seen first, then the other way round), and the filters narrow
the list by where the agents run, their risk and their owner. **Download CSV** gives the
agents shown as a spreadsheet, for a review or an auditor.

Tick the agents to act on, or all of those shown (the box in the table's header; on a phone,
**Choose all**), and the bar above the table offers what fits them:

- **Approve**, **Block**, **Unblock**, **Delete** and **Restore**, each agent on its own: one
  that can't be (approved without a sponsor, say) is left as it was, and AgentGov lists those
  left, with why. The reason you give is recorded for each of them in the ledger.
- **Edit…**: an owner, a team, sponsors to add or to take off (someone who left, say), a
  blueprint. Only what you fill in changes.
- **Adopt**, for those found on platforms: each with its maker as owner and sponsor where
  AgentGov knows them.
- **Classify…**: their classification under the EU AI Act, for the
  [classification register](evidence.md#a-classification-register).

Blocking or deleting an agent found on a platform changes AgentGov's registry, not the
platform: the dialog says which of them run where, to block them there too. Administrators
do all of these; the security team's role blocks and unblocks once the
[hand-off](secops.md) has reached *contain*; approvers classify.

In the CLI, name the agents: `agentgov agents block bot-a bot-b --reason "Incident 42"`, or
`agentgov agents update bot-a bot-b --remove-sponsor alice@example.com --add-sponsor
dana@example.com`. `agentgov agents list -q` prints only names, for other commands:
`agentgov agents approve $(agentgov agents list --status pending -q)`. A command that left
agents as they were says which, and why, and exits with 1.

The API takes up to 500 agents a call: `POST /v1/agents/bulk` with `action`, `agents` (names
or IDs), `reason` and, for `update`, `fields`: `owner`, `team`, `sponsors` (instead of each
one's own), `add_sponsors`, `remove_sponsors`, `blueprint`, `environment` and `risk_tier`;
for `classify`, `fields`: `category`, `role`, `basis` and `purpose`. It answers with the
agents `done`, and those `left`, each with `why`.

## Registry as code

The manifests that `agentgov export` writes (or the UI's **Export manifests**) are the
same ones `agentgov apply` and **Import manifests** read, so the registry can live in a Git
repository and be applied from CI with an `admin` key. (A `registrar` key can only submit
agents and tool servers for review, with `agentgov agents create` and `agentgov
toolservers create`.) Applying is idempotent: unchanged resources are reported as
unchanged. Changes made in the UI show
up in the next export, so the two ways of working can be mixed.
