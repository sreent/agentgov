# Contributing to AgentGov

Thanks for helping. AgentGov is young, so issues describing how you govern agents today
(and where that hurts) are as valuable as code.

## The one design rule

AgentGov composes established open-source projects and writes only what none of them
provides ([ADR 0001](docs/adr/0001-compose-established-projects.md)). Before adding a
feature, check whether Keycloak, OPA, agentgateway, Presidio or the OpenTelemetry Collector
already does it. If one does, configure or generate configuration for it instead of
reimplementing it. Policy logic belongs in Rego (`src/agentgov/policies`), not in Python.

Significant decisions get a short ADR in `docs/adr/`.

## Development setup

You need Python 3.11 or later; Docker for the image and end-to-end checks. The first
run of `scripts/ci.sh` creates `.venv` with the development dependencies and downloads
the pinned [OPA](https://www.openpolicyagent.org) binary into it:

```bash
scripts/ci.sh --setup && . .venv/bin/activate
```

Claude Code cloud sessions do this automatically (`.claude/hooks/session-start.sh`).

For API or UI work, run the control plane on its own, against a local SQLite file
([the control plane alone](docs/deploy/local.md#the-control-plane-alone)). For end-to-end
work, use the [Compose stack](docs/deploy/local.md#docker-compose), and rebuild the parts
that run AgentGov's image after a change:

```bash
docker compose -f deploy/compose/docker-compose.yml up -d --build control-plane processor gateway-config
```

## Checks

`scripts/ci.sh` runs the same checks as GitHub Actions, which calls it on every pull
request. Run it before you open one:

```bash
scripts/ci.sh             # ruff, the docs, opa fmt/check/test, pytest, the Helm chart, the image
scripts/ci.sh --e2e       # also: the demo and ledger verification against the Compose
                          # stack and against the Helm chart's pods run with Docker
scripts/ci.sh --kind      # also: the Helm chart on a kind cluster, with the same demo
scripts/ci.sh --matrix    # also: the tests on each Python 3.11-3.13 installed
```

Run `--e2e` when you change the processor, the Rego library, the gateway configuration,
the identity reconciler or the Helm chart. Its chart check runs the chart's pods with
Docker (`scripts/chart-on-docker.py`), so it works wherever Docker does, including Claude
Code's cloud sessions. `--kind` installs the chart on a real cluster; kind needs a Docker
host with cgroup v2, and the `e2e` workflow runs it on GitHub. `--e2e` uses its own Compose
project (`agentgov-ci`) and the stack's usual ports, so stop a running local stack first.

The docs check fails on a link to a file or heading that doesn't exist, and on a setting
without a comment: [configuration](docs/configuration.md#reference) is generated from the
comments in `src/agentgov/config.py`, so after changing a setting run
`scripts/settings-doc.py` to regenerate it.

On GitHub, the `ci` workflow runs the checks on Python
3.11, 3.12 and 3.13, and the `e2e` workflow runs the end-to-end check for pull requests
that change code or the deployment.

## Where things live

| Path | What |
|---|---|
| `src/agentgov/api` | The HTTP API's routes and authentication |
| `src/agentgov/registry` | The service layer: agents, blueprints, tool servers, model providers and usage, identity issuers, approvals, findings, risk, posture, discovery, platforms, instructions, decisions, features, destinations, manifests, API keys, access |
| `src/agentgov/secops` | The ledger as OCSF events, delivery to SIEMs and chats, alerts, hand-off levels |
| `src/agentgov/platforms` | Microsoft's services (Graph, the Power Platform API) and Copilot Studio threat detection |
| `src/agentgov/scanners` | Checks on agents' instructions: rules and the Granite Guardian client |
| `src/agentgov/identity` | Keycloak's admin client and the reconciler, single sign-on, the people agents act for, and the delegations agents pass on |
| `src/agentgov/opa` | Building and long-poll serving of bundles, Rego validation, the OPA client |
| `src/agentgov/policies` | The Rego library and its tests |
| `src/agentgov/processor` | The governance processor: the ExtMcp gRPC server, the guardrail webhook for model calls, external authorization for calls between agents, detectors, the Presidio client |
| `src/agentgov/gateway.py` | agentgateway's configuration, and the sidecar that keeps it current |
| `src/agentgov/telemetry.py` | OTLP ingestion: discovery, activity, detective controls, model usage |
| `src/agentgov/ledger.py` | The hash-chained evidence ledger |
| `src/agentgov/mcp_scan.py` | The MCP servers set up on a developer's machine (`agentgov mcp scan`) |
| `src/agentgov/models.py`, `src/agentgov/migrations` | The database schema and its migrations (Alembic) |
| `src/agentgov/config.py`, `src/agentgov/cli.py` | The settings, and the `agentgov` command |
| `src/agentgov/ui` | Admin UI (static files, no build step) |
| `deploy/compose`, `deploy/helm` | The Compose stack and the Helm chart (keep the chart's realm file in step with Compose's: CI compares them) |
| `deploy/kubernetes` | Values and manifests for the cloud guides |
| `examples` | Manifests, a demo MCP server, model, workload identity issuer and agent other agents call, a stand-in for the security team's tools, a developer's machine, and the demo agent |
| `docs` | The documentation ([index](docs/README.md)) and the ADRs |
| `scripts` | `ci.sh`, the docs checks, `chart-on-docker.py`, `new-migration.sh` and `gen-protos.sh` |
| `tests` | Unit and integration tests |

If you change the ExtMcp protocol definition, regenerate the stubs with
`scripts/gen-protos.sh`.

## Adding a feature

Organisations choose which features they use ([features](docs/features.md)), so a new
capability is a feature they can turn off. Add it to the catalog in
`src/agentgov/registry/features.py`, with its modes and what each does, and describe it in
`docs/features.md` (a test checks both). Then check its mode where it acts: in Rego with
`ctx.enforced(...)`, in the processor with the modes it reads from OPA, and in the control
plane with `features.mode(session, ...)`. A control that decides about calls should
support monitor mode: decide, record what it would have done, and let the call through.

## Changing the database schema

Every change to `src/agentgov/models.py` needs a migration in
`src/agentgov/migrations/versions`, and a test fails until it has one. Write it with:

```bash
scripts/new-migration.sh "Add model grants to blueprints"
```

Alembic compares a database built by the existing migrations with the models and writes
the difference as the next numbered revision. Read it before you commit: Alembic can't
tell a renamed column from a dropped and an added one, and moving data between columns is
yours to write. Keep each migration working on both PostgreSQL and SQLite (the helper
writes SQLite-compatible batch operations), and give new columns on existing tables a
`server_default` or make them nullable, because tables already have rows.

## Pull requests

* Keep each pull request focused, with tests for behaviour changes and docs for
  user-visible changes (including `docs/baseline-agent365.md` when parity changes).
* Write commit messages in the imperative mood ("Add …", "Fix …") and explain why.
* By contributing you agree that your contributions are licensed under the
  [Apache License 2.0](LICENSE).

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening an issue.
