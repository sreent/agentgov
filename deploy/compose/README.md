# Reference deployment (Docker Compose)

The whole platform on one machine: the AgentGov control plane and governance processor,
Keycloak, OPA, agentgateway, Presidio, the OpenTelemetry Collector, PostgreSQL, a demo
MCP server and a demo model. It is meant for evaluation and development. See [SECURITY.md](../../SECURITY.md)
before exposing it to anyone.

## Start

```bash
cp .env.example .env        # optional for local evaluation; required otherwise
docker compose up -d --build --wait
```

The first start takes a few minutes (image pulls, Keycloak realm import). Then, from
the repository root, register the examples and run the walkthrough:

```bash
pip install -e ".[demo]"
export AGENTGOV_TOKEN=dev-admin-token        # or your AGENTGOV_ADMIN_TOKEN
agentgov apply -f examples/manifests
python examples/agents/demo_agent.py
```

## Endpoints

| Port | Service | Notes |
|---|---|---|
| 8000 | Control plane | API (`/docs`), admin UI (`/ui`), OPA bundles, OTLP ingest, the MCP registry for developers' tools (`/registry`, once `mcp-registry` is on) |
| 8080 | agentgateway | MCP routes at `/mcp/<server>` and model routes at `/llm/<provider>`; requires a Keycloak-issued token |
| 8180 | Keycloak | Admin console user `admin`, password `KEYCLOAK_ADMIN_PASSWORD` (default `admin`); realm `agentgov` |
| 8181 | OPA | Query API, handy for debugging policies |
| 4317 / 4318 | OTel Collector | OTLP gRPC / HTTP for agents |
| 3000 | Langfuse | Only with the Langfuse override (below) |

PostgreSQL, Presidio, the processor, the demo MCP server and the demo model are only
reachable inside the Compose network. The MCP server and the model in particular are only
reachable through the gateway.

## Model providers' API keys

The gateway reads each model provider's API key from `model-keys/<provider name>` in this
directory, which is mounted into it, and into its config sidecar, as `/model-keys`. One
file per provider, holding only the key:

```bash
printf '%s' "$OPENAI_API_KEY" > model-keys/openai
agentgov models create openai --kind openai --trust verified
```

Git ignores the directory, apart from `demo`, the demo model's made-up key. To keep the
keys elsewhere, set `AGENTGOV_MODEL_KEYS_DIR` in `.env`. Until a provider's key is there,
its route answers 503. [Model calls](../../docs/models.md) has the rest.

## Signing in

The admin UI at <http://localhost:8000/ui> offers single sign-on through Keycloak. The
realm comes with four demo users, whose password is `AGENTGOV_DEMO_PASSWORD` (default
`dev-password`):

| User | Realm role | What they can do |
|---|---|---|
| `admin` | `agentgov-admin` | Everything |
| `alice` | `agentgov-approver` | Decide approval requests and findings; attest the agents they sponsor (the demo's `support-bot`) |
| `audrey` | `agentgov-auditor` | See everything, change nothing |
| `sam` | none (group `support`) | A person agents act for: signs in to the demo app `agentgov-demo-chat`, and to AgentGov to decide the approval requests sent to them, while `approvals-by-person` is on ([acting for people](../../docs/acting-for-people.md)) |

People without an `agentgov-*` role are turned away, unless the `approvals-by-person`
feature is on: then they see only the approval requests sent to them. Sign-ins, sign-outs and refusals
are recorded in the evidence ledger (`admin.login`, `admin.logout`,
`admin.login_denied`). Signing out also ends the Keycloak session, and a session lasts
at most `AGENTGOV_SESSION_HOURS` (default 8). The UI's **Access** page lists everyone who
has signed in, with their roles and open sessions, and admins can sign a person out there
(`agentgov access sign-out`), which is recorded as `admin.session_ended`.

To sign in your own people, connect your directory to the realm as an identity provider
(OIDC or SAML) or through user federation (LDAP, Active Directory), and give their groups
the `agentgov-*` realm roles, then delete the demo users. If the control plane is served
from another address, set `AGENTGOV_PUBLIC_URL` and update the `agentgov-admin` client's
redirect URI (`<public URL>/auth/callback`) and post-logout redirect URI
(`<public URL>/ui/`) in Keycloak. Another OIDC provider can be used directly instead of
Keycloak: set `AGENTGOV_OIDC_ISSUER`, its endpoints and the claim that carries roles (see
`src/agentgov/config.py`). For Microsoft Entra ID, AgentGov knows the endpoints;
[Setting it up](../../docs/platforms.md#setting-it-up) has the steps.

The CLI signs in the same way with `agentgov login`. API tokens still work next to
single sign-on: scripts and the CLI can use them, the UI accepts one on its sign-in page,
and the bootstrap token (`AGENTGOV_ADMIN_TOKEN`, default `dev-admin-token`) is the way in
when single sign-on is unavailable.

## Optional: Langfuse for trace exploration

```bash
docker compose -f docker-compose.yml -f docker-compose.langfuse.yml up -d --build
```

This adds Langfuse (web and worker, with ClickHouse, Redis and SeaweedFS) and makes the
collector send every agent and gateway trace to Langfuse as well as to the control plane.
Langfuse uses its own `langfuse` database on the stack's PostgreSQL server. Sign in at
<http://localhost:3000> as `admin@agentgov.local` / `agentgov-admin` (or the
`LANGFUSE_ADMIN_*` values from `.env`). The organisation, the *Agents* project and its API
keys are created on first start.

Every decision the gateway records in the evidence ledger carries the W3C trace ID of the
call, which agentgateway passes to the governance processor. With this override the
admin UI's ledger and agent pages link each decision to its trace in Langfuse (**Open
trace**), and `agentgov ledger tail --traces` prints the links. The override sets
`AGENTGOV_TRACE_URL` on the control plane; to link to another trace viewer instead, set it
to that viewer's trace URL with `{trace_id}` in place of the ID, for example
`http://jaeger:16686/trace/{trace_id}`. When agents propagate their own trace context to
the gateway, the trace contains the agent's spans as well as the gateway's.

Add `-f docker-compose.langfuse.yml` to every later `docker compose` command for this
stack (`ps`, `logs`, `down`), or set
`COMPOSE_FILE=docker-compose.yml:docker-compose.langfuse.yml` in `.env`.

## Optional: a classifier for agent instructions

AgentGov checks every agent's instructions (its system prompt) with its own rules. To
add IBM Granite Guardian as a second opinion, add the override:

```bash
docker compose -f docker-compose.yml -f docker-compose.guardian.yml up -d
```

It runs Granite Guardian 4.1 on llama.cpp's server, on the CPU. The first start
downloads the model (about 5 GB). Checks run in the background and take a few seconds
per criterion; with a GPU, serve the model with vLLM instead and set
`AGENTGOV_GUARDIAN_URL`. [Agent instructions](../../docs/instructions.md) has the details.

## Optional: Microsoft 365 and Copilot Studio agents

To connect AgentGov to Microsoft 365, set `AGENTGOV_M365_TENANT_ID`,
`AGENTGOV_M365_CLIENT_ID` and `AGENTGOV_M365_CLIENT_SECRET` in `.env` for a Microsoft
Entra app registration, then run `docker compose up -d` again. Its Microsoft Graph
application permissions decide what AgentGov reads: the Microsoft 365 agent catalog
(`CopilotPackages.Read.All`), Entra Agent ID (`AgentIdentity.Read.All`), the Purview
audit log (`AuditLogsQuery.Read.All`) and Defender alerts (`SecurityAlert.Read.All`).
The control plane syncs at start-up and every hour, and the **Platforms** page shows each
connection's state. Copilot Studio agents and their connectors are imported from a Power
Platform inventory export on the **Platforms** page, and need no configuration. If admins
sign in through Microsoft Entra ID instead of Keycloak (see `.env.example`), they can also
sync the Copilot Studio inventory, quarantine Copilot Studio agents, block Microsoft 365
agents and push the connector allowlist into Power Platform from AgentGov.

Copilot Studio threat detection (the feature `copilot-studio-threat-detection`) has
Copilot Studio ask AgentGov's policies before each tool call its agents make. Microsoft calls the
control plane, so `AGENTGOV_PUBLIC_URL` must be an HTTPS address it can reach.
[Agents on Microsoft 365 and Copilot Studio](../../docs/platforms.md) and [Connecting
AgentGov to Microsoft's services](../../docs/microsoft-connections.md) have the details.

## Configuration

| File | Purpose |
|---|---|
| `docker-compose.yml` | Services and their wiring; `AGENTGOV_*` variables are documented in `src/agentgov/config.py` |
| `.env.example` | Every secret the stack uses |
| `keycloak/agentgov-realm.json` | Realm with the control plane's provisioning client, the `agentgov-admin` sign-in client, the AgentGov roles, the demo users and the demo app people use agents from, `agentgov-demo-chat` (imported on first start) |
| `opa/config.yaml` | OPA bundle, decision log and status services (all served by the control plane) |
| `otel/collector.yaml` | OTLP in; spans to the control plane for discovery and activity, and the gateway's access logs of model calls for usage |
| `otel/langfuse.yaml` | Merged over the collector config by the Langfuse override |
| `postgres/init.sql` | Creates the Keycloak database |
| `model-keys/` | Model providers' API keys, one file per provider |

The agentgateway configuration is not a file in this directory: the control plane
generates it from the registry, and the `gateway-config` service (`agentgov
gateway-config`) fetches it every two seconds into the volume it shares with
agentgateway, which reloads it when it changes. The control plane never sees the model
keys: the sidecar is what checks that each provider's key is there.

## Upgrading

The control plane keeps its database schema up to date: when a new version starts, it
applies the migrations it brings, one control plane at a time. Back up PostgreSQL first,
then:

```bash
git pull
docker compose up -d --build --wait
docker compose exec control-plane agentgov db status    # the schema's revision
```

To review the changes before they are made, print them with
`docker compose run --rm control-plane db upgrade --sql`. To make them yourself, set
`AGENTGOV_DATABASE_AUTO_MIGRATE=false` on the control plane and run `docker compose run
--rm control-plane db upgrade` before starting the new version; it then refuses to start
until the schema is current. A database created before AgentGov had migrations is
adopted on its first upgrade, with its data. A newer schema than the version knows (after
going back to an older version) stops the control plane with a message: run the newer
version, or restore the backup.

## Reset

```bash
docker compose down -v      # removes all data, including Keycloak clients and the ledger
```

## Troubleshooting

* **`toomanyrequests` while pulling images**: Docker Hub rate limits anonymous pulls.
  Run `docker login`, or retry later.
* **The gateway answers 401**: the bearer token must come from the agent's own Keycloak
  client in the `agentgov` realm (`agentgov agents credentials <agent>`) and tokens expire
  after five minutes. Blocked agents' clients are disabled.
* **A model route answers 503, "The gateway has no API key for …"**: put the provider's
  key in `model-keys/<provider>` (see above); the route works within a few seconds.
* **Model usage stays empty**: the gateway's access logs reach the control plane through
  the collector. Check `docker compose logs otel-collector`.
* **A call is denied with "policy engine unavailable"**: OPA has not loaded a bundle yet.
  Check `docker compose logs opa`; bundle activation errors also raise a finding
  (`agentgov findings`).
* **Keycloak starts slowly**: the first start imports the realm and can take a minute;
  the control plane waits for it.
* **Single sign-on stops at Keycloak with "Invalid parameter: redirect_uri", or the UI
  says the identity provider could not complete the sign-in**: Keycloak imports the realm
  only on first start, so later changes to `AGENTGOV_PUBLIC_URL` or
  `AGENTGOV_OIDC_CLIENT_SECRET` must also be made on the `agentgov-admin` client in
  Keycloak (or start over with `docker compose down -v`). The control plane's log names
  the cause.
