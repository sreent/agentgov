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
- [x] What other components call: OPA's bundles and decision logs, the gateway's
  configuration, telemetry, Copilot Studio, AuthZEN, assertions. Copilot Studio's endpoint
  faces the internet: its caller is still checked from the headers before anything reads
  the body (`agentgov.web.asgi`), since Django reads every body whole before a view runs.
- [x] Single sign-on (cookies, redirects, back-channel logout).
- [x] The admin UI's files; then FastAPI goes, and the app runs the runtime itself. The
  files are Starlette's `StaticFiles`, as before (Starlette stays: the governance processor
  uses it too); `/`, `/openapi.json`, `/docs` and `/redoc` are Django's. What FastAPI
  answered stays in `tests/fastapi_answers.py`, for Django's answers to be checked against.

The data layer:

- [x] The transaction rules on Django, on SQLite and PostgreSQL, with tests: ledger last,
  job locks, row locks, changes after commit. Rather than prototypes, Django runs every
  transaction now (`agentgov.db`, `tests/test_transactions.py`): its checks and the ledger's
  entries come before Django commits, and `transaction.on_commit` announces what changed. The
  SQLAlchemy sessions the modules still use ride on Django's connection, in the same
  transaction, so modules can move one at a time. Connections are pooled, in psycopg's pool on
  PostgreSQL (15 a process, as SQLAlchemy's was) and in one of AgentGov's on SQLite.
- [x] Django models for every table, unmanaged, with a test that compares them with the
  migrated schema (`agentgov.db.models`, `tests/test_django_models.py`): the columns,
  keys, constraints, indexes and defaults, and the values each ORM writes, read by the
  other. Times are UTC without a zone and JSON is in `json` columns, as SQLAlchemy made
  them (`agentgov.db.fields`); Django's ORM uses the database whose transaction is open.
- [ ] The modules, the ledger first, each with its tests. A module that moves runs its
  queries on Django's ORM in the caller's transaction, and takes the transaction or, from a
  module still on SQLAlchemy, its session (`agentgov.db.Where`). Django's queries see what
  the session holds: it writes it first, as it does before its own queries (not before
  Django's savepoint statements, nor in its `no_autoflush` blocks). A model's `save()`
  writes the fields that changed since the row was read, as SQLAlchemy did: two
  transactions that change different fields of one row (a job and a person) keep both
  changes. Moved so far: the ledger, its retention and its witness (`agentgov.ledger`,
  `agentgov.retention`, `agentgov.witness`); sign-in, access and API keys
  (`agentgov.identity.sso`, `agentgov.identity.delegation`, `agentgov.registry.access`,
  `agentgov.registry.apikeys`, and the views and authentication that use them); tool
  servers, the MCP registry and developers' MCP servers, model providers, and identity
  issuers and their keys (`agentgov.registry.toolservers`, `mcp_registry`, `mcp_sightings`,
  `model_providers`, `identity_issuers`, `agentgov.identity.issuer_keys`). Each read gives
  another object, where SQLAlchemy's session gave the same one: a row is locked and read
  afresh before it is changed (`agentgov.db.lock`, on SQLite too), and what was changed
  before is saved first.
- [ ] Django's migrations: the first one matches the last Alembic revision; a release runs
  both; then Alembic goes.

## Consequences

* Two web frameworks ran side by side until the first stage ended, `/docs` listing the
  routes of both and the authorization matrix probing them all. Since, Django serves the API,
  answering as FastAPI did; `/openapi.json` is Django Ninja's description of the same routes.
* The second stage reimplements the data layer's rules rather than carrying them over. That
  is where the risk is, so it starts with prototypes, before any module moves.
* Python 3.11 stays supported. Django 5.2's support ends in April 2028; the next long-term
  release leaves Python 3.11 behind, as Python does in October 2027.
* AgentGov's settings (`AGENTGOV_*`) stay the only ones; Django's are built from them.
