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

## Check it against an imperfect organisation

Organisations don't have everything a feature might want: an administrator with every
role, every licence, a clean directory, owners who stay, a Kubernetes team, the ticketing
system AgentGov talks to. Before a change is done, answer these for it, in the code and in
the docs:

* **Who gets it, and can they act on it?** Every message and issue says what the
  person it reaches can do about it, with the role they have, which is often none.
* **What if they don't have what it needs?** A missing permission, licence, component or
  connection makes it say so and do less, not fail or pretend: it says what it needs, and
  who can give it.
* **What does it look like at scale?** With 300 agents and 1,000 issues: paging,
  filters, bulk actions, and one message rather than hundreds.
* **What if it's wrong?** People can undo what it did and see who did what, and why; an
  issue dismissed or a risk accepted keeps a reason and a date.
* **Does it use the same words?** One word for each thing, the one in the
  [glossary](docs/glossary.md), in the admin center, the CLI, messages and the docs. The API
  keeps its names; the glossary says what they are.
* **What does it claim?** Statuses, scores and reports say what AgentGov saw and how much
  of the estate that covers, not how a setting is configured.
* **What if it fails, or is restored from a backup?** It fails as its feature's failure
  behaviour says, and nothing it holds is lost without a trace.
* **Is the default safe?** No default that is fine on a laptop and dangerous on a network.

## Development setup

You need Python 3.11 or later; Node.js 22 or later for the admin UI; Docker for the image
and end-to-end checks. The first run of `scripts/ci.sh` creates `.venv` with the development
dependencies and downloads the pinned [OPA](https://www.openpolicyagent.org) binary into it,
and installs the admin UI's packages into `ui/node_modules`:

```bash
scripts/ci.sh --setup && . .venv/bin/activate
```

Claude Code cloud sessions do this automatically (`.claude/hooks/session-start.sh`).

For API or UI work, run the control plane on its own, against a local SQLite file
([the control plane alone](docs/deploy/local.md#the-control-plane-alone)). The admin UI is
React and TypeScript in `ui`, built with [Vite](https://vite.dev) into the package
(`src/agentgov/ui`, which isn't in git): `cd ui && npm run build` builds it there, and
`npm run dev` serves it at http://localhost:5173/ui/, reloading as you edit, in front of the
control plane at `AGENTGOV_URL` (by default http://127.0.0.1:8000). For end-to-end
work, use the [Compose stack](docs/deploy/local.md#docker-compose), and rebuild the parts
that run AgentGov's image after a change:

```bash
docker compose -f deploy/compose/docker-compose.yml up -d --build control-plane processor gateway-config
```

## Checks

`scripts/ci.sh` runs the same checks as GitHub Actions, which calls it on every pull
request. Run it before you open one:

```bash
scripts/ci.sh             # ruff, the docs, the Compose files, opa fmt/check/test, pytest,
                          # the admin UI (types, lint, build, in a browser), the Helm chart,
                          # the image
scripts/ci.sh --ui-only   # only the admin UI
scripts/ci.sh --e2e       # also: the demo and ledger verification against the Compose
                          # stack and against the Helm chart's pods run with Docker,
                          # and the inventory stack
scripts/ci.sh --kind      # also: the Helm chart on a kind cluster, with the same demo
scripts/ci.sh --spire     # --kind, with SPIRE on the cluster issuing the components'
                          # certificates
scripts/ci.sh --matrix    # also: the tests on each Python 3.11-3.13 installed
scripts/ci.sh --postgres  # also: the tests on PostgreSQL, in a throwaway container
```

Run `--e2e` when you change the processor, the Rego library, the gateway configuration,
the identity reconciler or the Helm chart. Its chart check runs the chart's pods with
Docker (`scripts/chart-on-docker.py`), so it works wherever Docker does, including Claude
Code's cloud sessions. `--kind` installs the chart on a real cluster; kind needs a Docker
host with cgroup v2, and the `e2e` workflow runs it on GitHub, with and without `--spire`. `--e2e` uses its own Compose
project (`agentgov-ci`) and the stack's usual ports, so stop a running local stack first.

The docs check fails on a link to a file or heading that doesn't exist, and on a setting
without a comment: [configuration](docs/configuration.md#reference) is generated from the
comments in `src/agentgov/config.py`, so after changing a setting run
`scripts/settings-doc.py` to regenerate it.

On GitHub, the `ci` workflow runs the checks on Python 3.11, 3.12 and 3.13, on PostgreSQL,
and the admin UI in a browser (its report, traces and the control plane's log are kept as
an artifact when a test fails). The `e2e` workflow runs the end-to-end check for pull
requests that change code or the deployment.

### The admin UI

`npm run check` in `ui` checks the types of the build's and the tests' code and lints all of
it ([ESLint](https://eslint.org), with React's rules of hooks, and no HTML set from data: what
the API returns is rendered as text); `npm run build` checks the app's types and builds it into
the package. The tests in `ui/e2e` then drive the admin UI's main flows in Chromium with
[Playwright](https://playwright.dev): signing in and out, the menu and every page it opens,
registering, approving, blocking and unblocking agents and tool servers, the approvals
inbox, issues (dismissed, reopened, risk accepted, resolved several at once), API keys,
what an auditor and a role for one team see, the ledger and its chain, the compliance
report and evidence pack, and features' modes. They run against a control plane of their
own, started for them on port 8765 with the examples' manifests applied
(`scripts/ui-test-server.py`), which serves the build in the package, and fail on any script
error in the page. Install the packages and Chromium once, build, then run them:

```bash
cd ui && npm ci && npx playwright install chromium
npm run build
npx playwright test                 # all of them; --headed to watch, --ui to step through
npx playwright test e2e/agents.spec.ts
npx playwright show-report          # after a failure: each failed test's trace
```

`npx playwright test` uses a control plane already answering on port 8765 as it is: start
one with `python scripts/ui-test-server.py` to keep it between runs. `scripts/ci.sh`, like
CI, always starts its own. The control plane's log is in
`ui/test-results/control-plane.log`.

A test finds what it checks the way people do, by role, label, heading and text
(`getByRole('button', { name: 'Block server' })`), never by CSS class or DOM structure,
so that the tests hold however the UI is built. They share one control plane and run one
at a time: a test that changes something other tests see, such as a feature's mode, puts
it back.

### The tests on PostgreSQL

The tests run on SQLite, each on a copy of a database the migrations built. Production
runs on PostgreSQL, so `--postgres` (and `--e2e`) runs them again there: each test on a
database of its own, copied from a template. To use a PostgreSQL of your own, give the
tests its URL, as a role that may create databases:
`AGENTGOV_TEST_POSTGRES_URL=postgresql+psycopg://postgres:secret@127.0.0.1:5432/postgres pytest`
(the migrations' test empties the database the URL names).

## Where things live

| Path | What |
|---|---|
| `src/agentgov/api` | The ASGI app (`app.py`: the API, the admin UI's files, the runtime's lifespan) and the rules of who may call what (`auth.py`, `reach.py`) |
| `src/agentgov/web` | The HTTP API on Django and Django Ninja ([ADR 0007](docs/adr/0007-django.md)) |
| `src/agentgov/registry` | The service layer: agents, blueprints, tool servers, model providers and usage, identity issuers, approvals, findings, risk, posture, discovery, platforms, instructions, decisions, features, destinations, manifests, API keys, access |
| `src/agentgov/secops` | The ledger as OCSF events, delivery to SIEMs and chats, alerts, hand-off levels |
| `src/agentgov/platforms` | Microsoft's services (Graph, the Power Platform API) and Copilot Studio threat detection |
| `src/agentgov/scanners` | Checks on agents' instructions: rules and the Granite Guardian client |
| `src/agentgov/identity` | Keycloak's admin client and the reconciler, single sign-on, the people agents act for, and the delegations agents pass on |
| `src/agentgov/opa` | Building, signing and long-poll serving of bundles, Rego validation, the OPA client |
| `src/agentgov/policies` | The Rego library and its tests |
| `src/agentgov/processor` | The governance processor: the ExtMcp gRPC server, the guardrail webhook for model calls, external authorization for calls between agents and external processing for their answers, detectors, the Presidio client, the classifier's second opinion on traffic |
| `src/agentgov/gateway.py` | agentgateway's configuration, and the sidecar that keeps it current |
| `src/agentgov/telemetry.py` | OTLP ingestion: discovery, activity, detective controls, model usage |
| `src/agentgov/ledger.py`, `src/agentgov/retention.py`, `src/agentgov/compliance.py` | The hash-chained evidence ledger, its checkpoints, retention and archives, and the compliance reports |
| `src/agentgov/coordination.py` | Several control-plane replicas: changes to every replica, the leader, jobs one at a time |
| `src/agentgov/tls.py` | Mutual TLS between the components, and making their certificates |
| `src/agentgov/mcp_scan.py` | The MCP servers set up on a developer's machine (`agentgov mcp scan`) |
| `src/agentgov/db` | The database's connections and transactions, which Django runs with the rules every transaction keeps; the tables as Django models (`models.py`); and the SQLAlchemy sessions the modules use until they move to Django's ORM ([ADR 0007](docs/adr/0007-django.md)) |
| `src/agentgov/models.py`, `src/agentgov/migrations` | The database schema and its migrations (Alembic) |
| `src/agentgov/config.py`, `src/agentgov/cli.py` | The settings, and the `agentgov` command |
| `ui` | The admin UI: React and TypeScript (`src`: a module per page in `pages`, the sign-in page and the menu in `shell`, and what pages share in `components` and `lib`), built with Vite into `src/agentgov/ui` (not in git), and its browser tests (`e2e`, Playwright) |
| `deploy/compose`, `deploy/helm` | The Compose stack and the Helm chart (keep the chart's realm file in step with Compose's: CI compares them) |
| `deploy/kubernetes` | Values and manifests for the cloud guides |
| `examples` | Manifests, a demo MCP server, model, workload identity issuer and agent other agents call, a stand-in for the security team's tools, a developer's machine, and the demo agent |
| `docs` | The documentation ([index](docs/README.md)) and the ADRs |
| `scripts` | `ci.sh`, the docs checks, `chart-on-docker.py`, `check-inventory.py`, `ui-test-server.py`, `new-migration.sh` and `gen-protos.sh` |
| `tests` | Unit and integration tests |

If you change a protocol definition in `src/agentgov/processor/proto` (agentgateway's
ExtMcp, or the part of Envoy's external processing the processor serves), regenerate the
stubs with `scripts/gen-protos.sh`.

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

While the modules move to Django's ORM ([ADR 0007](docs/adr/0007-django.md)), the Django
models in `src/agentgov/db/models.py` name the same tables: change them in step, and
`tests/test_django_models.py` checks them against the database the migrations build. A
module that has moved (the ADR lists them) queries with Django's models in the caller's
transaction, and takes the transaction or, from a module still on SQLAlchemy, its session
(`agentgov.db.Where`); it calls those with `db.orm(tx)`. It hands them none of Django's
objects to change: SQLAlchemy wouldn't write what they change. A model's `save()` writes
the fields that changed since the row was read, as SQLAlchemy did, so set a JSON field to
a new value rather than changing the one there. The module's tests move with it, onto
`db.transaction()` and Django's models.

## Pull requests

* Keep each pull request focused, with tests for behaviour changes and docs for
  user-visible changes (including `docs/baseline-agent365.md` when parity changes).
* Write commit messages in the imperative mood ("Add …", "Fix …") and explain why.
* By contributing you agree that your contributions are licensed under the
  [Apache License 2.0](LICENSE).

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening an issue.
