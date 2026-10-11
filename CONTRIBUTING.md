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

For API or UI work, the control plane runs on its own against a local SQLite file
(`agentgov.db`); Keycloak, OPA and the gateway are optional and their reconcilers stay
idle when they are not configured:

```bash
AGENTGOV_ADMIN_TOKEN=dev agentgov server     # then open http://localhost:8000/ui
```

For end-to-end work, use the Compose stack in [`deploy/compose`](deploy/compose/README.md)
and rebuild the image with `docker compose up -d --build control-plane processor`.

## Checks

`scripts/ci.sh` runs the same checks as GitHub Actions, which calls it on every pull
request. Run it before you open one:

```bash
scripts/ci.sh             # ruff, opa fmt/check/test, pytest, the Helm chart, the image
scripts/ci.sh --e2e       # also: the Compose stack, the demo agent and ledger verification
scripts/ci.sh --kind      # also: the Helm chart on a kind cluster, with the same demo
scripts/ci.sh --matrix    # also: the tests on each Python 3.11-3.13 installed
```

Run `--e2e` when you change the processor, the Rego library, the gateway configuration or
the identity reconciler, and `--kind` when you change the Helm chart (kind needs a Docker
host with cgroup v2; the `e2e` workflow runs it on GitHub). It uses its own Compose project and the stack's usual ports, so
stop a running local stack first. On GitHub, the `ci` workflow runs the checks on Python
3.11, 3.12 and 3.13, and the `e2e` workflow runs the end-to-end check for pull requests
that change code or the deployment.

## Where things live

| Path | What |
|---|---|
| `src/agentgov/registry` | Registry and lifecycle: agents, blueprints, tool servers, approvals, findings, risk, discovery |
| `src/agentgov/models.py`, `src/agentgov/migrations` | The database schema and its migrations (Alembic) |
| `src/agentgov/policies` | The Rego library and its tests |
| `src/agentgov/opa` | Bundle building and serving, Rego validation |
| `src/agentgov/identity` | Keycloak reconciler |
| `src/agentgov/gateway.py` | agentgateway configuration generator |
| `src/agentgov/processor` | ExtMcp governance processor and detectors |
| `src/agentgov/api` | HTTP API |
| `src/agentgov/ui` | Admin UI (static files, no build step) |
| `deploy/compose`, `deploy/helm` | The Compose stack and the Helm chart (keep the chart's realm file in step with Compose's: CI compares them) |

If you change the ExtMcp protocol definition, regenerate the stubs with
`scripts/gen-protos.sh`.

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
