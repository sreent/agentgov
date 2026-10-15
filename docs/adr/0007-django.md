# ADR 0007: Django for the control plane

Status: accepted (2026-10-15). It replaces [ADR 0005](0005-python-control-plane.md)'s FastAPI
and SQLAlchemy; Python stays.

## Context

The control plane is FastAPI over SQLAlchemy 2, with Alembic for migrations: 191 routes in
18 files, 38 tables and 32 migrations, data access in 167 of the package's files, 1,293
Python tests and 38 browser tests. Its maintainers want Django: one framework for the API,
the data, the migrations and an admin site, with its conventions, its documentation and the
many people who know it.

The data layer keeps rules that the security review relies on, and that any replacement must
keep too:

* A transaction's ledger entries are written last, just before it commits, behind the chain's
  head lock, so that they never deadlock with the rows decisions lock.
* Decisions lock their rows and read them afresh: two approvers take turns.
* What a transaction changed reaches the reconcilers and the other replicas once it commits,
  never before.
* A job's transaction commits only while the job still holds its lock.
* SQLite writers take their lock up front, and every timestamp is UTC.

## Decision

Django 5.2, the long-term release that runs on Python 3.11, with
[Django Ninja](https://django-ninja.dev) for the API, in two stages. Each ships on its own,
and neither changes what callers see: paths, bodies, status codes and headers stay as they
are, so the CLI, the processor, the admin UI, agents and integrations notice nothing.

1. **The HTTP layer.** Route groups move from FastAPI to Django one at a time. Until a group
   has moved, FastAPI serves it, in the same process and on the same port: one ASGI app hands
   each request to the framework that has its path (`agentgov.api.app`), and a path moves
   whole. The data stays in SQLAlchemy in this stage: each route already runs its own
   transaction, so none of the rules above changes. Views run in a thread pool, as FastAPI's
   did, since Django would run sync views one at a time under ASGI; async views run on the
   server's event loop, where the OPA bundles' long poll waits.
2. **The data layer.** The Django ORM replaces SQLAlchemy, and Django's migrations replace
   Alembic's, once each rule above has a Django equivalent with tests of its own: a
   transaction that writes the ledger last and checks a job's lock before it commits,
   `transaction.on_commit` for what changed, `select_for_update` for decisions, and SQLite's
   immediate transactions. The models name the existing tables, columns and constraints, so
   databases are adopted rather than rebuilt; one release runs both tools, taking a database
   from its last Alembic revision to Django's first migration.

The authorization matrix, the promise tests and the browser tests are the gate for every
group that moves.

## Plan

The HTTP layer, a group at a time (`src/agentgov/web`):

- [x] The foundation: Django's settings built from AgentGov's, the composed ASGI app, threaded
  views, JSON and error answers as FastAPI wrote them, the API's description at `/docs` with
  every route in it, and health, version and `/v1/me` on Django.
- [x] Features, rules, instructions, access, identity issuers, models, MCP servers, security
  operations, access packages. Their routes under an agent's path (`/v1/agents/{ref}/...`)
  move with the registry's, whose `POST /v1/agents/{ref}/{action}` takes those paths too.
- [x] Evidence (downloads and archives), platforms, the registry, governance.
- [ ] What other components call: OPA's bundles and decision logs, the gateway's
  configuration, telemetry, Copilot Studio, AuthZEN, assertions.
- [ ] Single sign-on (cookies, redirects, back-channel logout).
- [ ] The admin UI's files; then FastAPI goes, and the app runs the runtime itself.

The data layer:

- [ ] Prototypes of the transaction rules on SQLite and PostgreSQL, with tests: ledger last,
  job locks, row locks, changes after commit.
- [ ] Django models for every table, unmanaged, with a test that compares them with the
  migrated schema.
- [ ] The modules, the ledger first, each with its tests.
- [ ] Django's migrations: the first one matches the last Alembic revision; a release runs
  both; then Alembic goes.

## Consequences

* Two web frameworks run side by side until the first stage ends. `/docs` lists the routes
  of both, and the authorization matrix probes them all.
* The second stage reimplements the data layer's rules rather than carrying them over. That
  is where the risk is, so it starts with prototypes, before any module moves.
* Python 3.11 stays supported. Django 5.2's support ends in April 2028; the next long-term
  release leaves Python 3.11 behind, as Python does in October 2027.
* AgentGov's settings (`AGENTGOV_*`) stay the only ones; Django's are built from them.
