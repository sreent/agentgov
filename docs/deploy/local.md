# Run AgentGov on your machine

Three ways, for evaluation and development:

| | What runs | For |
|---|---|---|
| [Docker Compose](#docker-compose) | The whole stack, with the demo's tool server, model and stand-ins | Trying AgentGov, the demo, end-to-end development |
| [Just the inventory](#just-the-inventory) | The control plane and PostgreSQL, with Compose | An inventory of the agents on your platforms, their issues, without the gateway |
| [Kubernetes with kind](#kubernetes-with-kind) | The Helm chart on a local cluster | Working on the chart, rehearsing a Kubernetes install |
| [The control plane alone](#the-control-plane-alone) | The API and the admin UI, on a SQLite file | Working on the API or the UI |

None of them is for anything others rely on: [one server](server.md) is, with Compose, and
[Deploying AgentGov](README.md) covers Kubernetes and the cloud. [SECURITY.md](../../SECURITY.md)
says what to do before anyone else can reach it.

## Docker Compose

You need Docker with Compose v2, Python 3.11 or later for the CLI and the demo, and about
4 GB of free memory: the stack uses about 2.5 GB, most of it Presidio's language models
and Keycloak ([requirements](../requirements.md)).

```bash
git clone https://github.com/sreent/ai-agent-governance-platform.git
cd ai-agent-governance-platform
docker compose -f deploy/compose/docker-compose.yml up -d --build --wait

python -m venv .venv && . .venv/bin/activate
pip install -e ".[demo]"
export AGENTGOV_TOKEN=dev-admin-token
agentgov apply -f examples/manifests
python examples/agents/demo_agent.py
```

The first start takes a few minutes: images are pulled, and Keycloak imports AgentGov's
realm. `agentgov apply` registers the examples: blueprints, the demo CRM tool server, a
model provider, agents, a policy, an identity issuer, the security team's destinations, and
the hand-off to them at `inform`.
The demo then walks through each control with a real MCP client (the
[demo](../demo.md) lists the steps).

The stack listens on this machine only: its defaults, the tokens and the demo users'
password, are known to everyone. For others to use it, run it as [one server](server.md):
your own secrets, HTTPS in front, and none of the demo's parts.

### Endpoints

| Port | Service | Notes |
|---|---|---|
| 8000 | Control plane | Admin UI at `/ui`, API reference at `/docs`; OPA bundles, OTLP ingest, and the MCP registry for developers' tools (`/registry`, once `mcp-registry` is on) |
| 8080 | agentgateway | Tool servers at `/mcp/<server>`, model providers at `/llm/<provider>` and agents that serve A2A at `/a2a/<agent>`, for callers with a token from Keycloak |
| 8180 | Keycloak | Admin console user `admin`, password `KEYCLOAK_ADMIN_PASSWORD` (default `admin`); realm `agentgov` |
| 8181 | OPA | Query API, over mutual TLS: callers show a certificate from the stack's authority (below) |
| 4317 / 4318 | OpenTelemetry Collector | OTLP over gRPC / HTTP, for agents' traces |
| 9200 | Demo workload identity issuer | A stand-in Kubernetes cluster that gives out service account tokens, for the demo's agent without a client secret ([agents' own identities](../agent-identity.md)) |
| 9300 | Demo sink | A stand-in for the security team's SIEM, Splunk, Slack and Teams: what the demo's destinations sent is at `/received` ([security operations](../secops.md)) |
| 3000 | Langfuse | Only with the Langfuse override (below) |

PostgreSQL, Presidio, the processor, the demo CRM tool server, the demo model and the demo
billing agent are only reachable inside the Compose network, and the last three only
through the gateway. AgentGov's components talk to each other over mutual TLS
([production](../production.md#mutual-tls-between-components)): on its first start, the
`certs` service makes the stack's own authority, a certificate for each component and the
key that signs OPA's bundles, on the `certs` volume, and each component mounts only its
own; `docker compose run --rm --entrypoint sh certs -c "agentgov internal-certs /certs
--renew && chmod a+r /certs/*/tls.key"` renews them, and the components take theirs within
a minute. To ask OPA yourself, use OPA's certificate for instance:
`docker compose cp opa:/tls ./opa-tls`, then `curl --cacert opa-tls/ca.crt --cert
opa-tls/tls.crt --key opa-tls/tls.key https://localhost:8181/v1/data`. The billing agent ([examples/agents/billing](../../examples/agents/billing/server.py))
is the agent other agents call in the demo ([agent to agent](../agent-to-agent.md)). The
demo's stand-ins are not for real use.

### Signing in

The admin UI at <http://localhost:8000/ui> signs people in through Keycloak. The realm
comes with five demo users, whose password is `AGENTGOV_DEMO_PASSWORD` (default
`dev-password`):

| User | Realm role | What they can do |
|---|---|---|
| `admin` | `agentgov-admin` | Everything |
| `alice` | `agentgov-approver` | Decide approval requests and issues; attest the agents they sponsor (the demo's `support-bot`) |
| `sofia` | `agentgov-secops` | The security team: see everything, and triage, contain or decide as far as the hand-off to [security operations](../secops.md) allows |
| `audrey` | `agentgov-auditor` | See everything, change nothing |
| `sam` | none (group `support`) | A person agents act for: signs in to the demo app `agentgov-demo-chat`, and to AgentGov to decide the approval requests sent to them, while `approvals-by-person` is on ([acting for people](../acting-for-people.md)) |
| `dana` | none (group `developers`) | A developer: signs in from an MCP client to the `coding-assistant` agent, which acts for them at the gateway ([developer tools](../developer-tools.md#signing-in-at-the-gateway)) |

People without an `agentgov-*` role are turned away, unless the `approvals-by-person`
feature is on: then they see only the approval requests sent to them. Sign-ins, sign-outs
and refusals are recorded in the evidence ledger (`admin.login`, `admin.logout`,
`admin.login_denied`). Signing out also ends the Keycloak session, and a session lasts at
most `AGENTGOV_SESSION_HOURS` (default 8). The **Access** page lists everyone who has
signed in, with their roles and open sessions, and administrators can sign a person out
there (`agentgov access sign-out`), which is recorded as `admin.session_ended`.

To sign in your own people, connect your directory to the realm as an identity provider
(OIDC or SAML) or through user federation (LDAP, Active Directory), give their groups the
`agentgov-*` realm roles, and delete the demo users. If the control plane is served from
another address, set `AGENTGOV_PUBLIC_URL` and update the `agentgov-admin` client's
redirect URI (`<public URL>/auth/callback`) and post-logout redirect URI
(`<public URL>/ui/`) in Keycloak. Your own identity provider (Microsoft Entra ID, Okta,
Google, Ping, any OpenID Connect provider) can sign people in instead of Keycloak: set
`AGENTGOV_OIDC_ISSUER`, the client's ID and secret in `.env`, and AgentGov reads the
provider's endpoints from its discovery document
([your identity provider](../administration.md#your-identity-provider)).

The CLI signs in the same way with `agentgov login`. API tokens work next to single
sign-on: scripts and the CLI can use them, the UI accepts one on its sign-in page, and the
bootstrap token (`AGENTGOV_ADMIN_TOKEN`, default `dev-admin-token`) is the way in when
single sign-on is unavailable.

### Settings and secrets

`deploy/compose/.env` holds the secrets and the settings `docker-compose.yml` passes on,
and `deploy/compose/docker-compose.override.yml` any other setting
([configuration](../configuration.md#docker-compose)). Compose reads the override only when
it isn't given files with `-f`: with one, run Compose in `deploy/compose` without `-f`, or
add `-f deploy/compose/docker-compose.override.yml` to the commands on this page. Two folders
hold credentials that only one part mounts:

* **Model providers' API keys**, in `deploy/compose/model-keys/<provider>`, one file per
  provider holding only its key, read by the gateway and its configuration sidecar. Until a
  provider's key is there, its route answers 503 ([model calls](../models.md)):

  ```bash
  printf '%s' "$OPENAI_API_KEY" > deploy/compose/model-keys/openai
  agentgov models create openai --kind openai --trust verified
  ```

* **Destinations' credentials**, in `deploy/compose/destination-secrets/<destination>`:
  Slack's and Teams' webhook URLs, Splunk's HTTP Event Collector token, or headers for
  OpenTelemetry and webhook destinations, read by the control plane when it sends
  ([security operations](../secops.md)):

  ```bash
  printf '%s' "$SLACK_WEBHOOK_URL" > deploy/compose/destination-secrets/team-slack
  agentgov destinations create team-slack --kind slack
  agentgov secops level inform
  ```

Git ignores both folders, apart from the demo's files (the demo model's made-up key, and
destinations that point at the demo sink). `AGENTGOV_MODEL_KEYS_DIR` and
`AGENTGOV_DESTINATION_SECRETS_DIR` in `.env` keep them elsewhere.

### Optional: Langfuse, to explore traces

```bash
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.langfuse.yml up -d --build
```

This adds Langfuse (web and worker, with ClickHouse, Redis and SeaweedFS), and the
collector sends every agent and gateway trace to Langfuse as well as to the control plane.
Langfuse keeps its data in its own `langfuse` database on the stack's PostgreSQL. Sign in at
<http://localhost:3000> as `admin@agentgov.local` / `agentgov-admin` (or the
`LANGFUSE_ADMIN_*` values from `.env`); the organisation, the *Agents* project and its API
keys are created on first start.

Every decision the gateway records carries the W3C trace ID of the call. With this
override, the ledger and agent pages link each decision to its trace in Langfuse (**Open
trace**), and `agentgov ledger tail --traces` prints the links. The override sets
`AGENTGOV_TRACE_URL`; to link to another trace viewer, set it in
`docker-compose.override.yml` to that viewer's trace URL with `{trace_id}` in place of the ID,
such as `http://localhost:16686/trace/{trace_id}` for Jaeger. When
agents pass their own trace context to the gateway, the trace holds the agent's spans as
well as the gateway's.

Add `-f deploy/compose/docker-compose.langfuse.yml` to every later `docker compose`
command for the stack (`ps`, `logs`, `down`), or set
`COMPOSE_FILE=docker-compose.yml:docker-compose.langfuse.yml` in `.env`. Plan on about 3 GB
more memory.

### Optional: a classifier

AgentGov checks agents' instructions (their system prompts) and their traffic with its own
rules. To add IBM Granite Guardian as a second opinion on both:

```bash
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.guardian.yml up -d
```

It runs Granite Guardian 4.1 on llama.cpp's server, on the CPU, for the control plane
([agent instructions](../instructions.md)) and the governance processor
([detection](../detection.md)). The first start downloads the model (about 5 GB); plan on
about 8 GB more memory. Each verdict takes a few seconds on the CPU, so leave the
`traffic-classifier` feature in monitor mode, where the processor asks in the background.
With a GPU, serve the model with vLLM instead and set `AGENTGOV_GUARDIAN_URL`.

To try the feature without downloading the model, point AgentGov at the demo's stand-in,
which flags only text that asks to wire money (step 21 of the demo):

```bash
AGENTGOV_GUARDIAN_URL=http://demo-model:9100/guardian/v1 docker compose -f deploy/compose/docker-compose.yml up -d
```

### Optional: Microsoft 365 and Copilot Studio

Set `AGENTGOV_M365_TENANT_ID`, `AGENTGOV_M365_CLIENT_ID` and `AGENTGOV_M365_CLIENT_SECRET` in
`.env` for a Microsoft Entra app registration, then run `docker compose up -d` again. Its
Microsoft Graph application permissions decide what AgentGov reads: the Microsoft 365 agent
catalog (`CopilotPackages.Read.All`), Entra Agent ID (`AgentIdentity.Read.All`), who made
each Copilot Studio agent (`User.Read.All`), the Purview audit log
(`AuditLogsQuery.Read.All`), Defender alerts (`SecurityAlert.Read.All`) and Entra access
packages (`EntitlementManagement.Read.All`). The
control plane syncs at start-up and every hour, and the **Platforms** page shows each
connection's state. Copilot Studio agents and their connectors are imported from a Power
Platform inventory export on the **Platforms** page, with no configuration. When
administrators sign in through Microsoft Entra ID instead of Keycloak (see `.env.example`),
they can also sync the Copilot Studio inventory, quarantine Copilot Studio agents, block
Microsoft 365 agents and push the connector allowlist into Power Platform from AgentGov.

Copilot Studio threat detection (the feature `copilot-studio-threat-detection`) has Copilot
Studio ask AgentGov's policies before each tool call its agents make. Microsoft calls the
control plane, so `AGENTGOV_PUBLIC_URL` must be an HTTPS address Microsoft can reach.
[Agents on Microsoft 365 and Copilot Studio](../platforms.md) and
[connecting AgentGov to Microsoft's services](../microsoft-connections.md) have the details.

### Optional: without Presidio

Presidio takes about 1.5 GB of the stack's 2.5 GB. Without it, the governance processor still
checks for secrets, prompt injection and poisoned tools, but not personal data, and the
**Features** page says so; the demo's personal-data steps fail:

```bash
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.no-presidio.yml up -d --build --wait
```

To start with every control watching rather than stopping, set
`AGENTGOV_FEATURE_PRESET=monitor` in `.env` before the first start
([starting points](../features.md#starting-points)).

### What's in `deploy/compose`

| File | What it is |
|---|---|
| `docker-compose.yml` | The services and how they connect |
| `docker-compose.inventory.yml` | The control plane and PostgreSQL alone ([below](#just-the-inventory)) |
| `docker-compose.no-presidio.yml`, `docker-compose.langfuse.yml`, `docker-compose.guardian.yml` | Overrides: without Presidio, with Langfuse, with Granite Guardian (above) |
| `docker-compose.server.yml`, `caddy/`, `https/` | For others to rely on: the stack on [one server](server.md), with HTTPS from Caddy, and your own certificate if you have one |
| `.env.example` | Every secret the stack uses, and its optional settings |
| `keycloak/agentgov-realm.json` | The realm, imported on Keycloak's first start: the control plane's provisioning client, the `agentgov-admin` sign-in client, the AgentGov roles, the demo users and the demo app people use agents from, `agentgov-demo-chat` |
| `opa/config.yaml` | OPA's bundle, decision log and status services, all served by the control plane on its internal port, and the key bundles are signed with |
| `otel/collector.yaml` | OTLP in; spans to the control plane for discovery and activity, and the gateway's access logs of model calls for usage |
| `otel/langfuse.yaml` | Merged over the collector's configuration by the Langfuse override |
| `postgres/init.sql` | Creates Keycloak's database |
| `model-keys/`, `destination-secrets/` | Credentials, one file each (above) |

agentgateway's configuration is not a file here: the control plane generates it from the
registry, and the `gateway-config` service (`agentgov gateway-config`) fetches it every two
seconds into the volume it shares with agentgateway, which reloads it when it changes. The
control plane never sees the model keys: the sidecar checks that each provider's key is
there.

### Upgrading

The control plane keeps its database schema current: when a new version starts, it applies
the migrations it brings. Back up PostgreSQL first ([backing up](../backup.md#with-compose)),
then:

```bash
git pull
docker compose -f deploy/compose/docker-compose.yml up -d --build --wait
docker compose -f deploy/compose/docker-compose.yml exec control-plane agentgov db status
```

`docker compose ... run --rm control-plane db upgrade --sql` prints the changes before they
are made. To make them yourself, set `AGENTGOV_DATABASE_AUTO_MIGRATE=false` (in
`docker-compose.override.yml`) and run
`docker compose ... run --rm control-plane db upgrade` before starting the new version,
which then refuses to start until the schema is current. A schema newer than the version
knows (after going back to an older version) stops the control plane with a message: run
the newer version, or restore the backup.

Keycloak imports AgentGov's realm on its first start only. If yours was imported before
agents could have their own identities, give the control plane's service account the two
roles it now needs: at <http://localhost:8180>, open the `agentgov` realm, then Clients,
`agentgov-control-plane`, Service account roles, Assign role, and assign
`realm-management`'s `manage-identity-providers` and `view-identity-providers`. Until then,
identity issuers show an error saying so.

### Starting over

```bash
docker compose -f deploy/compose/docker-compose.yml down -v   # removes all data: agents, Keycloak's clients, the ledger
```

### Troubleshooting

* **`toomanyrequests` while pulling images**: Docker Hub rate-limits anonymous pulls. Run
  `docker login`, or try later.
* **The gateway answers 401**: the bearer token must come from the agent's own Keycloak
  client in the `agentgov` realm (`agentgov agents credentials <agent>`), and tokens expire
  after five minutes. Blocked agents' clients are disabled.
* **A model route answers 503, "The gateway has no API key for …"**: put the provider's
  key in `model-keys/<provider>`; the route works within a few seconds.
* **Model usage stays empty**: the gateway's access logs reach the control plane through
  the collector. Check `docker compose ... logs otel-collector`.
* **Calls are denied with "policy engine unavailable"**: OPA has no bundle yet. Check
  `docker compose ... logs opa`; bundle errors also raise an issue (`agentgov issues`).
  While no control at the gateway is enforced, such calls go through unchecked instead,
  and the ledger records them as `Not checked`
  ([when something is down](../features.md#when-something-is-down)).
* **Single sign-on stops at Keycloak with "Invalid parameter: redirect_uri"**, or the UI
  says the identity provider could not complete the sign-in: Keycloak imports the realm
  only on its first start, so later changes to `AGENTGOV_PUBLIC_URL` or
  `AGENTGOV_OIDC_CLIENT_SECRET` must be made on the `agentgov-admin` client in Keycloak too
  (or start over). The control plane's log names the cause.

## Just the inventory

To keep an inventory of the agents on your platforms (Microsoft 365, Copilot Studio, AWS,
Google Cloud, Salesforce, Databricks, Microsoft Foundry), with their issues sent to the
people responsible, AgentGov needs neither the gateway nor what checks its calls. The
control plane and PostgreSQL do, in about 200 MB of memory:

```bash
echo "AGENTGOV_ADMIN_TOKEN=$(openssl rand -hex 32)" >> deploy/compose/.env
docker compose -f deploy/compose/docker-compose.inventory.yml up -d --build --wait
```

Open <http://localhost:8000/ui> with that token (`grep ADMIN_TOKEN deploy/compose/.env`).
Unlike the full stack, this one has no token everybody knows: it won't start without one.
It listens on this machine only; for others to reach it, [one server](server.md#the-inventory)
puts HTTPS in front. On its first start the control plane applies the inventory starting point: the gateway's
features off, and discovery, posture checks, issues, management rules and the platforms on
([starting points](../features.md#starting-points)). Every setting in `deploy/compose/.env`
reaches the control plane: the platforms' credentials
([other platforms](../other-platforms.md), [Microsoft](../microsoft-connections.md)),
`AGENTGOV_OIDC_*` to sign administrators in with your identity provider, and
`AGENTGOV_SMTP_*` for issues' emails ([configuration](../configuration.md)).

It runs as its own Compose project, `agentgov-inventory`, with its own database, so the full
stack beside it starts afresh (not at the same time: both use port 8000). On Kubernetes the
same choice is a [profile](kubernetes.md#profiles), and adding the gateway later is an
upgrade that keeps the registry, its issues and the ledger.

## Kubernetes with kind

[kind](https://kind.sigs.k8s.io) runs a Kubernetes cluster in Docker. The CI script installs
the chart on one, with the demo's tool server, model and stand-ins beside it, and runs the
demo; `--keep` leaves the cluster running afterwards:

```bash
scripts/ci.sh --kind-only --keep
```

It needs Docker on a host with cgroup v2, and fetches kind, kubectl and Helm into `.venv`.
With `--spire`, it installs SPIRE on the cluster first, from the SPIFFE project's charts,
and SPIRE issues the components' certificates
([production](../production.md#workload-identities-from-spire)). Afterwards, forward the
ports to reach AgentGov in the cluster:

```bash
export PATH="$PWD/.venv/bin:$PATH"
kubectl -n agentgov port-forward svc/agentgov-control-plane 8000:8000 &
kubectl -n agentgov port-forward svc/agentgov-gateway 8080:8080 &
kubectl -n agentgov port-forward svc/agentgov-keycloak 8180:8080 &
kubectl -n agentgov get secret agentgov -o jsonpath='{.data.admin-token}' | base64 -d
```

Remove it with `kind delete cluster --name agentgov-ci`. To install the chart on a cluster
of your own instead, see [Kubernetes](kubernetes.md).

## The control plane alone

For work on the API or the admin UI, the control plane runs on its own, against a SQLite
file (`agentgov.db`) in the folder it starts in. Keycloak, OPA and the gateway are optional:
their parts stay idle while they aren't configured. The admin UI is built into the package
from `ui` (with Node.js 22 or later); until it is, `/ui` says how to build it.

```bash
pip install -e ".[dev]"
(cd ui && npm ci && npm run build)            # the admin UI, into src/agentgov/ui
AGENTGOV_ADMIN_TOKEN=dev agentgov server      # then open http://localhost:8000/ui
```

For work on the admin UI, `cd ui && npm run dev` serves it at http://localhost:5173/ui/ and
reloads it as you edit, sending API calls to the control plane at `AGENTGOV_URL` (by default
http://127.0.0.1:8000).

[CONTRIBUTING.md](../../CONTRIBUTING.md) has the rest of the development setup.
