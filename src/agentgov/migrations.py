"""The database schema's migrations: Django's (``agentgov/db/migrations``,
docs/adr/0007-django.md).

The control plane brings its database up to date when it starts
(``AGENTGOV_DATABASE_AUTO_MIGRATE``, on by default), and ``agentgov db upgrade``
does the same by hand, for example from a deployment job that runs before
the new version starts.

Alembic's migrations built the schema until Django's took over, and Django's first builds
the schema Alembic's last revision (``ALEMBIC_LAST``) left. A database Alembic's migrations
took that far is taken over as it is: Django's first migration is recorded as applied rather
than run, since its tables are there. One they left at an earlier revision, and one from
before AgentGov had migrations, are refused: the last version that ran Alembic's migrations
(``LAST_WITH_ALEMBIC``) brings them that far first.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING, Any

from django.core.management import call_command
from django.db import connections
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.recorder import MigrationRecorder

if TYPE_CHECKING:
    from agentgov.db import Database

log = logging.getLogger(__name__)

# Django's name for AgentGov's tables (agentgov.db.apps), whose migrations these are.
APP = "agentgov"
# Alembic's last revision, whose schema Django's first migration builds.
ALEMBIC_LAST = "0032"
# The last version of AgentGov that ran Alembic's migrations (the commit on main): it takes a
# database from any of their revisions, or from before them, to their last.
LAST_WITH_ALEMBIC = "8470de7c22be"
# Tables every AgentGov database has had: one of them without a record of a migration means
# a database from before migrations.
_PRE_MIGRATION_TABLES = {"agents", "blueprints", "ledger"}
# PostgreSQL advisory lock held while migrating, so replicas starting together
# migrate one at a time ("AGMG").
_LOCK_KEY = 0x41474D47


class SchemaError(RuntimeError):
    """The database's schema is not the one this version of AgentGov needs."""


@dataclass(frozen=True)
class Status:
    # The last migration applied: Django's, once one is, else Alembic's last revision.
    current: str | None
    # The last of this version's migrations.
    head: str
    # Those it would apply, in order.
    pending: list[str]

    @property
    def up_to_date(self) -> bool:
        return not self.pending

    @property
    def from_alembic(self) -> bool:
        """Alembic's migrations left the database, and Django's take over at the next
        upgrade: the first recorded as applied, not run."""
        return self.current == ALEMBIC_LAST


@cache
def django_migrations() -> list[str]:
    """Django's migrations, in the order they apply."""
    graph = MigrationLoader(None, ignore_no_migrations=True).graph
    [leaf] = graph.leaf_nodes(APP)
    return [name for app, name in graph.forwards_plan(leaf) if app == APP]


def head() -> str:
    """The last of this version's migrations."""
    return django_migrations()[-1]


@contextmanager
def _django(db: Database) -> Iterator[Any]:
    """Django's connection to the database, closed (back to its pool) after."""
    try:
        yield connections[db.alias]
    finally:
        connections[db.alias].close()


def _applied(connection: Any) -> list[str]:
    """Django's migrations the database has had, in order; refused if it has had one this
    version doesn't know."""
    recorder = MigrationRecorder(connection)
    applied = {name for app, name in recorder.applied_migrations() if app == APP}
    unknown = sorted(applied - set(django_migrations()))
    if unknown:
        raise SchemaError(
            f"the database's schema is at migration {unknown[-1]!r}, which this version of "
            "AgentGov does not know: it was probably migrated by a newer version. Run that "
            "version, or restore a backup taken before the upgrade"
        )
    return [name for name in django_migrations() if name in applied]


def _alembic(connection: Any) -> str | None:
    """Where Alembic's migrations left a database Django's haven't migrated: at their last
    revision, or nowhere (an empty database). Refused anywhere else, and if it is from before
    AgentGov had migrations."""
    with connection.cursor() as cursor:
        tables = set(connection.introspection.table_names(cursor))
        revision = None
        if "alembic_version" in tables:
            cursor.execute("SELECT version_num FROM alembic_version")
            row = cursor.fetchone()
            revision = row[0] if row else None
    if revision == ALEMBIC_LAST:
        return revision
    if revision is not None:
        raise SchemaError(_older(f"is at Alembic's revision {revision}"))
    if tables & _PRE_MIGRATION_TABLES:
        raise SchemaError(_older("is from before AgentGov had migrations"))
    return None


def _older(where: str) -> str:
    return (
        f"the database's schema {where}, and this version of AgentGov takes over only from "
        f"Alembic's last revision ({ALEMBIC_LAST}): bring it up to date first with the last "
        f"version that ran Alembic's migrations (AgentGov at commit {LAST_WITH_ALEMBIC}: "
        "agentgov db upgrade), then with this one"
    )


def status(db: Database) -> Status:
    with _django(db) as connection:
        applied = _applied(connection)
        current = applied[-1] if applied else _alembic(connection)
    return Status(
        current=current,
        head=head(),
        pending=[name for name in django_migrations() if name not in applied],
    )


def check(db: Database) -> None:
    """Raise SchemaError unless the schema is the one this version needs."""
    state = status(db)
    if not state.up_to_date:
        raise SchemaError(
            f"the database's schema is at revision {state.current or 'none'} but this version "
            f"of AgentGov needs {state.head}: run `agentgov db upgrade`, or set "
            "AGENTGOV_DATABASE_AUTO_MIGRATE=true"
        )


@contextmanager
def _one_at_a_time(db: Database) -> Iterator[None]:
    """Replicas starting together migrate one at a time (PostgreSQL): a lock, held on a
    connection of its own while one does."""
    if db.sqlite:
        yield
        return
    connection = db.connect()
    try:
        connection.execute("SELECT pg_advisory_lock(%s)", (_LOCK_KEY,))
        try:
            yield
        finally:
            # At once, rather than once the server sees the connection close.
            with suppress(Exception):
                connection.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_KEY,))
    finally:
        with suppress(Exception):
            connection.close()


def upgrade(db: Database) -> list[str]:
    """Bring the schema up to date; returns the migrations applied, in order."""
    with _one_at_a_time(db), _django(db) as connection:
        done = _applied(connection)
        from_alembic = not done and _alembic(connection) == ALEMBIC_LAST
        pending = [name for name in django_migrations() if name not in done]
        if pending:
            if from_alembic:
                log.info("taking the schema over from Alembic's last revision (%s)", ALEMBIC_LAST)
            call_command(
                "migrate",
                APP,
                database=db.alias,
                # The first, recorded as applied: Alembic's migrations built its tables.
                fake_initial=from_alembic,
                interactive=False,
                verbosity=0,
            )
    for step in pending:
        log.info("database migrated to %s", step)
    return pending


def upgrade_sql(db: Database) -> str:
    """The SQL that ``upgrade`` would run, for review by a database administrator."""
    state = status(db)
    if not state.pending:
        return ""
    statements: list[str] = []
    with _django(db) as connection:
        recorder = MigrationRecorder(connection)
        if not recorder.has_table():
            with connection.schema_editor(collect_sql=True, atomic=False) as editor:
                editor.create_model(recorder.Migration)
            statements += editor.collected_sql
        loader = MigrationLoader(connection)
        for name in state.pending:
            migration = loader.graph.nodes[(APP, name)]
            # The first is recorded only where Alembic's migrations built its tables.
            recorded_only = state.from_alembic and name == django_migrations()[0]
            steps = [] if recorded_only else loader.collect_sql([(migration, False)])
            steps.append(_recorded(name))
            # Each with its record, in one transaction, as migrate applies it.
            if migration.atomic and connection.features.can_rollback_ddl:
                ops = connection.ops
                steps = [ops.start_transaction_sql(), *steps, ops.end_transaction_sql()]
            statements += steps
    return "\n".join(statements) + "\n"


def _recorded(name: str) -> str:
    """The statement that records Django's migration ``name``, one of this version's own,
    as applied."""
    values = f"'{APP}', '{name}', CURRENT_TIMESTAMP"
    return f"INSERT INTO django_migrations (app, name, applied) VALUES ({values});"  # noqa: S608
