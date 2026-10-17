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
  SQLAlchemy sessions the modules used rode on Django's connection, in the same transaction,
  so that modules could move one at a time. Connections are pooled, in psycopg's pool on
  PostgreSQL (15 a process, as SQLAlchemy's was) and in one of AgentGov's on SQLite.
- [x] Django models for every table, unmanaged, with a test that compares them with the
  migrated schema (`agentgov.db.models`, `tests/test_django_models.py`): the columns,
  keys, constraints, indexes and defaults, and the values as the databases hold them.
  Times are UTC without a zone and JSON is in `json` columns, as SQLAlchemy made them
  (`agentgov.db.fields`); Django's ORM uses the database whose transaction is open.
- [x] The modules, the ledger first, each with its tests. A module that moved ran its queries
  on Django's ORM in the caller's transaction, and took the transaction or, from a module
  still on SQLAlchemy, its session: Django's queries saw what the session held, which it
  wrote first, as it did before its own queries. A model's `save()` writes the fields that
  changed since the row was read, as SQLAlchemy did: two transactions that change different
  fields of one row (a job and a person) keep both changes. They moved in this order: the
  ledger, its retention and its witness (`agentgov.ledger`, `agentgov.retention`,
  `agentgov.witness`); sign-in, access and API keys (`agentgov.identity.sso`,
  `agentgov.identity.delegation`, `agentgov.registry.access`, `agentgov.registry.apikeys`, and
  the views and authentication that use them); tool servers, the MCP registry and developers'
  MCP servers, model providers, and identity issuers and their keys
  (`agentgov.registry.toolservers`, `mcp_registry`, `mcp_sightings`, `model_providers`,
  `identity_issuers`, `agentgov.identity.issuer_keys`); findings, the issues they are and
  their kinds, their messages and daily digests, their tickets in service desks,
  destinations, and what goes to the security team (`agentgov.registry.findings`,
  `finding_types`, `issues`, `digest`, `tickets`, `destinations`, `agentgov.notify`,
  `agentgov.ticketing`, `agentgov.secops`); features and their exceptions, policies, teams,
  the people in the directory, where an organisation starts, and what integrations keep
  between runs (`agentgov.registry.features`, `scopes`, `policies`, `teams`, `people`,
  `start`, and the state that connections, threat detection, posture scans and the OPA
  bundle keep); what platforms report of their agents and how each sync went, the connector
  allowlist, access packages and their assignments, and management rules and the agents they
  match (`agentgov.registry.platforms`, `connector_policy`, `access_packages`, `rules`);
  approval requests, risk signals, agents' daily activity and model usage, and their
  instructions (`agentgov.registry.approvals`, `risk`, `model_usage`, `instructions`, and
  `discovery`'s counters, which add up in the database rather than in memory); agents and
  blueprints, with everything that reads or changes them: their lifecycle, discovery,
  decisions and telemetry, platforms' inventories, posture scans, rules, the identity
  provider's clients, the gateway's configuration and the OPA bundle
  (`agentgov.registry.agents`, `blueprints`, `discovery`, `decisions`, `agentgov.telemetry`,
  `agentgov.identity.keycloak`, `agentgov.gateway`, `agentgov.opa.bundle`, and the rest of
  the registry); and last, the views, the compliance reports, the components' health and
  the runtime (`agentgov.web`, `agentgov.compliance`, `agentgov.health`, `agentgov.runtime`).
  An agent is read with its blueprint, as SQLAlchemy's relationship read it
  (`Agent.objects`). Each read gives another object, where SQLAlchemy's session gave the
  same one: a row is locked and read afresh before it is changed (`agentgov.db.lock`, on
  SQLite too), and what was changed before is saved first. A part of a transaction that
  rolls back on its own (one of many findings acted on at once, say) is Django's savepoint
  (`Transaction.savepoint`). Then the sessions went, with what let them share Django's
  transaction: the modules take the transaction they run in (`agentgov.db.Transaction`).
  SQLAlchemy's models of the tables stayed for Alembic alone (`agentgov.models`) until
  Django's migrations took over, and its engine for the migrations and the replicas'
  coordination.
- [x] Django's migrations: the first one matches the last Alembic revision; a release runs
  both. Django's first migration (`agentgov/db/migrations/0001_initial.py`) builds the schema
  Alembic's last revision (0032) leaves, which `tests/test_migrations.py` checks on SQLite
  and PostgreSQL: the same tables, columns, keys, constraints, indexes and defaults. Django's
  PostgreSQL backend adds no indexes of its own for that (`agentgov.db.postgresql`: none of
  the `_like` ones for `LIKE` on keys). `agentgov db upgrade`, and the control plane as it
  started, ran both, one replica at a time (a PostgreSQL advisory lock): Alembic's up to
  their last, then Django's, the first recorded as applied rather than run, since Alembic's
  built its tables (`agentgov.migrations`). `agentgov db status` and `--sql` covered both, and
  a migration of either that the version didn't know was refused. New migrations are
  Django's (`scripts/new-migration.sh`, `makemigrations`); SQLAlchemy's models of the
  tables, which Alembic's were written from, went. Two differences stayed on a database
  Django's migrations built, in its one foreign key, from an agent to its blueprint. Django
  set it to null when the blueprint went, not the database, as Django 5.2 declares no such
  rule. And the database checked it at commit, as Django makes keys, after the transaction
  had locked the chain's head: a transaction that gave an agent a blueprint another had
  locked, then appended to the ledger, deadlocked with it, which the chart's end-to-end run
  found. AgentGov's schema editors make keys as Alembic's schema had them, checked as each
  statement writes them, and with the database's own rule for a key Django sets to null;
  Django's second and third migrations make again the keys a database has otherwise
  (`agentgov.db.keys`, `tests/test_concurrency.py`). Django 6's `DB_SET_NULL` can replace
  the rule once AgentGov runs on it.
- [x] The replicas' coordinator off SQLAlchemy's engine: its `LISTEN`, the leader's lock and
  jobs' locks are on PostgreSQL connections of its own, outside the pool, made as Django
  makes the others (`Database.connect`). SQLAlchemy was left for what Alembic needed: the
  engine its migrations ran on, given the database's URL as AgentGov read it; and the tests
  that built and compared schemas with it.
- [x] Alembic goes once a version that runs both has brought databases to its last revision.
  AgentGov had no release yet, so that version is a commit on main (`8470de7c22be`, the
  merge of Django's migrations) rather than a release, and Alembic went in the next change.
  A database at Alembic's last revision is taken over as before: Django's first migration
  recorded, not run, and Alembic's record kept, for that version to run on it again. One
  Alembic's migrations left at an earlier revision, or one from before AgentGov had
  migrations, is refused, and the message names that commit, which brings it up to date
  (`agentgov.migrations`, `tests/test_migrations.py`). SQLAlchemy went with Alembic: the
  database's URL is read as SQLAlchemy read it (`agentgov.db.parse_url`), and the tests
  read schemas with Django's introspection.

## Consequences

* Two web frameworks ran side by side until the first stage ended, `/docs` listing the
  routes of both and the authorization matrix probing them all. Since, Django serves the API,
  answering as FastAPI did; `/openapi.json` is Django Ninja's description of the same routes.
* The second stage reimplements the data layer's rules rather than carrying them over. That
  is where the risk is, so it starts with prototypes, before any module moves.
* Python 3.11 stays supported. Django 5.2's support ends in April 2028; the next long-term
  release leaves Python 3.11 behind, as Python does in October 2027.
* AgentGov's settings (`AGENTGOV_*`) stay the only ones; Django's are built from them.
