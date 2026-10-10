# Reference deployment (Docker Compose)

The whole platform on one machine: the AgentGov control plane and governance processor,
Keycloak, OPA, agentgateway, Presidio, the OpenTelemetry Collector, PostgreSQL and a demo
MCP server. It is meant for evaluation and development. See [SECURITY.md](../../SECURITY.md)
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
| 8000 | Control plane | API (`/docs`), admin UI (`/ui`), OPA bundles, OTLP ingest |
| 8080 | agentgateway | MCP routes at `/mcp/<server>`; requires a Keycloak-issued token |
| 8180 | Keycloak | Admin console user `admin`, password `KEYCLOAK_ADMIN_PASSWORD` (default `admin`); realm `agentgov` |
| 8181 | OPA | Query API, handy for debugging policies |
| 4317 / 4318 | OTel Collector | OTLP gRPC / HTTP for agents |
| 3000 | Langfuse | Only with the Langfuse override (below) |

PostgreSQL, Presidio, the processor and the demo MCP server are only reachable inside
the Compose network. The MCP server in particular is only reachable through the gateway.

## Signing in

The admin UI at <http://localhost:8000/ui> offers single sign-on through Keycloak. The
realm comes with three demo users, whose password is `AGENTGOV_DEMO_PASSWORD` (default
`dev-password`):

| User | Realm role | What they can do |
|---|---|---|
| `admin` | `agentgov-admin` | Everything |
| `alice` | `agentgov-approver` | Decide approval requests and findings; attest the agents they sponsor (the demo's `support-bot`) |
| `audrey` | `agentgov-auditor` | See everything, change nothing |

People without an `agentgov-*` role are turned away. Sign-ins, sign-outs and refusals
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
`src/agentgov/config.py`).

API tokens still work next to single sign-on: the CLI uses them, the UI accepts one on
its sign-in page, and the bootstrap token (`AGENTGOV_ADMIN_TOKEN`, default
`dev-admin-token`) is the way in when single sign-on is unavailable.

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

## Optional: Microsoft 365 and Copilot Studio agents

To bring the organisation's Microsoft 365 agent catalog into the registry, set
`AGENTGOV_M365_TENANT_ID`, `AGENTGOV_M365_CLIENT_ID` and `AGENTGOV_M365_CLIENT_SECRET`
in `.env` for a Microsoft Entra app with the Microsoft Graph application permission
`CopilotPackages.Read.All`, then run `docker compose up -d` again. The control plane
syncs at start-up and every hour. Copilot Studio agents and their connectors are
imported from a Power Platform inventory export on the **Platforms** page, and need no
configuration. [Agents on Microsoft 365 and Copilot Studio](../../docs/platforms.md) has
the details.

## Configuration

| File | Purpose |
|---|---|
| `docker-compose.yml` | Services and their wiring; `AGENTGOV_*` variables are documented in `src/agentgov/config.py` |
| `.env.example` | Every secret the stack uses |
| `keycloak/agentgov-realm.json` | Realm with the control plane's provisioning client, the `agentgov-admin` sign-in client, the AgentGov roles and the demo users (imported on first start) |
| `opa/config.yaml` | OPA bundle, decision log and status services (all served by the control plane) |
| `otel/collector.yaml` | OTLP in; spans to the control plane for discovery and activity |
| `otel/langfuse.yaml` | Merged over the collector config by the Langfuse override |
| `postgres/init.sql` | Creates the Keycloak database |

The agentgateway configuration is not a file in this directory: the control plane
generates it from the registry into the shared `gateway-config` volume, and agentgateway
reloads it when it changes.

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
