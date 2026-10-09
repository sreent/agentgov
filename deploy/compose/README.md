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

## Optional: Langfuse for trace exploration

```bash
docker compose -f docker-compose.yml -f docker-compose.langfuse.yml up -d --build
```

This adds Langfuse (web and worker, with ClickHouse, Redis and MinIO) and makes the
collector send every agent and gateway trace to Langfuse as well as to the control plane.
Langfuse uses its own `langfuse` database on the stack's PostgreSQL server. Sign in at
<http://localhost:3000> as `admin@agentgov.local` / `agentgov-admin` (or the
`LANGFUSE_ADMIN_*` values from `.env`). The organisation, the *Agents* project and its API
keys are created on first start.

Add `-f docker-compose.langfuse.yml` to every later `docker compose` command for this
stack (`ps`, `logs`, `down`), or set
`COMPOSE_FILE=docker-compose.yml:docker-compose.langfuse.yml` in `.env`.

## Configuration

| File | Purpose |
|---|---|
| `docker-compose.yml` | Services and their wiring; `AGENTGOV_*` variables are documented in `src/agentgov/config.py` |
| `.env.example` | Every secret the stack uses |
| `keycloak/agentgov-realm.json` | Realm with the control plane's provisioning client (imported on first start) |
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
