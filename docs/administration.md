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
you. `agentgov logout` ends it. `AGENTGOV_TOKEN` takes precedence over a saved session.
The session appears on the **Access** page like any other, and the ledger's
`admin.login` entry says it came from the CLI.

To sign in on a machine you reach over SSH, forward a port and fix the CLI to it:
`ssh -L 8765:127.0.0.1:8765 HOST`, then `agentgov login --no-browser --port 8765` on that
machine, and open the link it prints in your local browser. For scripts and CI
pipelines, use an API key instead.

## Roles

| Role | Can |
|---|---|
| `admin` | Everything below, plus agent lifecycle, blueprints, tool servers, policies, credentials, API keys, platform syncs and the connector allowlist |
| `approver` | Read everything; decide approval requests; resolve, dismiss and reopen findings; attest the agents it sponsors |
| `auditor` | Read everything, including the ledger and the list of API keys; change nothing |
| `registrar` | Register agents and tool servers, which wait for an admin's review (for CI pipelines and developers); it cannot read the registry |
| `service` | The internal endpoints used by OPA, the governance processor and the OpenTelemetry Collector |

People who sign in with single sign-on get their roles from the identity provider (see the
[deployment guide](../deploy/compose/README.md#signing-in)) each time they sign in. To take
someone's access away, remove their role there, then sign them out on the **Access**
page so that their open sessions end too. The same page lists everyone who has signed
in (or been refused) and every API key, for access reviews. API keys have one role each.
The UI only shows the controls a role may use; the API enforces the roles either way.

## Tasks

| Task | Admin UI | CLI | API |
|---|---|---|---|
| Register an agent | Agents → **Register agent** | `agentgov agents create NAME --blueprint B --sponsor S [--approve]` | `POST /v1/agents` |
| Edit an agent | Agent → **Edit** | `agentgov agents update REF --owner …` | `PATCH /v1/agents/{ref}` |
| Approve, block, unblock, delete, restore | Agent toolbar | `agentgov agents approve\|block\|unblock\|delete\|restore REF` | `POST /v1/agents/{ref}/{action}` |
| Adopt a discovered agent | Agent → **Adopt** | `agentgov agents lifecycle REF adopt` | `POST /v1/agents/{ref}/adopt` |
| Delete a deleted agent permanently | Agent → **Delete permanently** | `agentgov agents purge REF` | `DELETE /v1/agents/{ref}` |
| Attest an agent | Agent → **Attest** | `agentgov agents attest REF` | `POST /v1/agents/{ref}/attest` |
| Show or rotate an agent's client secret | Agent → Identity → **Show secret** / **Rotate** | `agentgov agents credentials REF [--rotate]` | `POST /v1/agents/{ref}/credentials` |
| See or recompute risk | Agent → Risk → **Recalculate** | `agentgov agents risk REF [--refresh]` | `GET /v1/agents/{ref}/risk`, `POST /v1/agents/{ref}/risk/refresh` |
| Create, edit, delete blueprints | Policies → **New blueprint**, **Edit**, **Delete** | `agentgov blueprints create\|update\|delete` | `POST /v1/blueprints`, `PATCH`/`DELETE /v1/blueprints/{name}` |
| Register, edit, delete tool servers | Tool servers → **Register tool server**, **Edit**, **Delete** | `agentgov toolservers create\|update\|delete` | `POST /v1/toolservers`, `PATCH`/`DELETE /v1/toolservers/{name}` |
| Approve, block, unblock a tool server | Tool servers → **Approve**, **Block server**, **Unblock** | `agentgov toolservers approve\|block\|unblock NAME` | `POST /v1/toolservers/{name}/{action}` |
| Accept a changed tool definition | Tool catalog → **Approve new definition** | `agentgov toolservers approve-tool NAME TOOL` | `POST /v1/toolservers/{name}/tools/{tool}/approve` |
| Add, edit, enable, disable, delete policies | Policies → **Add policy**, **Edit**, **Disable**/**Enable**, **Delete** | `agentgov policies create\|update\|enable\|disable\|delete` | `POST /v1/policies`, `PUT`/`DELETE /v1/policies/{name}` |
| Ask what policy would decide | Policies → **What if** | `agentgov policies evaluate --server crm --tool delete_customer --agent support-bot` | `POST /v1/policies/evaluate` |
| Apply manifests | Policies → **Import manifests** | `agentgov apply -f DIR` | `POST /v1/apply` |
| Export manifests | Policies → **Export manifests** | `agentgov export` | `GET /v1/export` |
| Decide an approval request | Approvals → **Approve** / **Deny** | `agentgov approvals approve\|deny ID` | `POST /v1/approvals/{id}/approve\|deny` |
| Resolve, dismiss, reopen findings | Findings | `agentgov findings resolve\|dismiss\|reopen ID` | `POST /v1/findings/{id}/{action}` |
| Browse, verify and export the ledger | Ledger → filters, **Verify chain**, **Export JSONL** | `agentgov ledger tail --agent A`, `ledger verify`, `ledger export` | `GET /v1/ledger`, `/v1/ledger/verify`, `/v1/ledger/export` |
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

Every CLI command has `--help`. Commands that cannot be undone (`purge`, `delete` of
blueprints, tool servers and policies, `apikeys revoke`) ask for confirmation unless you
pass `--yes`.

## Registry as code

The manifests that `agentgov export` writes (or the UI's **Export manifests**) are the
same ones `agentgov apply` and **Import manifests** read, so the registry can live in a Git
repository and be applied from CI with an `admin` key. (A `registrar` key can only submit
agents and tool servers for review, with `agentgov agents create` and `agentgov
toolservers create`.) Applying is idempotent: unchanged resources are reported as
unchanged. Changes made in the UI show
up in the next export, so the two ways of working can be mixed.
