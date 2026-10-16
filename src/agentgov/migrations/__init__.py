"""The database schema's history: Alembic's migrations, then Django's (docs/adr/0007-django.md).

The control plane brings its database up to date when it starts
(``AGENTGOV_DATABASE_AUTO_MIGRATE``, on by default), and ``agentgov db upgrade``
does the same by hand, for example from a deployment job that runs before
the new version starts.

Alembic's migrations (``versions/``, one per change) built the schema until Django's
took over (``agentgov/db/migrations``): Django's first builds the schema Alembic's last
leaves. This version runs both, one migrator at a time: Alembic's up to their last, then
Django's, the first of them recorded as applied rather than run, since its tables are
there. A later version drops Alembic's, once databases have been through this one.

A database created before AgentGov had migrations (by SQLAlchemy's
``create_all``) is adopted on its first upgrade: the baseline migration creates
only the tables it lacks, and the later migrations apply to it like any other.
"""

from __future__ import annotations

import io
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.script.revision import RevisionError
from alembic.util import CommandError
from django.core.management import call_command
from django.db import connections
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.recorder import MigrationRecorder
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection, Engine

if TYPE_CHECKING:
    from agentgov.db import Database

log = logging.getLogger(__name__)

LOCATION = Path(__file__).parent
# The schema that create_all built when migrations were introduced.
BASELINE = "0001"
# Tables every AgentGov database has had: one of them without a version table
# means a database from before migrations.
_PRE_MIGRATION_TABLES = {"agents", "blueprints", "ledger"}
# PostgreSQL advisory lock held while migrating, so replicas starting together
# migrate one at a time ("AGMG").
_LOCK_KEY = 0x41474D47
# Django's name for AgentGov's tables (agentgov.db.apps), whose migrations these are.
APP = "agentgov"


class SchemaError(RuntimeError):
    """The database's schema is not the one this version of AgentGov needs."""


@dataclass(frozen=True)
class Status:
    # The last migration applied: Django's, once one is, else Alembic's revision.
    current: str | None
    # The last of this version's migrations.
    head: str
    # Those it would apply, in order: Alembic's revisions, then Django's migrations.
    pending: list[str]
    # Created by create_all before AgentGov had migrations; adopted on upgrade.
    unversioned: bool = False

    @property
    def up_to_date(self) -> bool:
        return not self.pending and not self.unversioned


# ------------------------------------------------------------------------ Alembic's


@cache
def scripts() -> ScriptDirectory:
    return ScriptDirectory(str(LOCATION))


def alembic_head() -> str:
    """Alembic's last revision, whose schema Django's first migration builds."""
    revision = scripts().get_current_head()
    assert revision is not None
    return revision


def _config(
    connection: Connection | None = None, *, output: io.StringIO | None = None, **attributes: Any
) -> Config:
    cfg = Config(output_buffer=output)
    cfg.set_main_option("script_location", str(LOCATION))
    if connection is not None:
        cfg.attributes["connection"] = connection
    cfg.attributes.update(attributes)
    return cfg


def _pending(current: str | None) -> list[str]:
    """Alembic's revisions between ``current`` and its last, oldest first."""
    try:
        steps = list(scripts().iterate_revisions(alembic_head(), current))
    except (CommandError, RevisionError) as exc:  # a revision this version doesn't have
        raise SchemaError(_unknown(current)) from exc
    return [s.revision for s in reversed(steps)]


def _unknown(revision: str | None) -> str:
    return (
        f"the database's schema is at revision {revision!r}, which this version of AgentGov "
        "does not know: it was probably migrated by a newer version. Run that version, or "
        "restore a backup taken before the upgrade"
    )


def _unversioned(connection: Connection) -> bool:
    tables = set(inspect(connection).get_table_names())
    return "alembic_version" not in tables and bool(tables & _PRE_MIGRATION_TABLES)


@contextmanager
def _migrating(engine: Engine) -> Iterator[Connection]:
    """A connection in a transaction, for Alembic's migrations."""
    with engine.connect() as connection:
        sqlite = connection.dialect.name == "sqlite"
        if sqlite:
            # SQLite alters a table by rebuilding it, which trips foreign keys; the
            # setting only takes effect outside a transaction.
            connection.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
        try:
            with connection.begin():
                yield connection
        finally:
            if sqlite:
                connection.connection.dbapi_connection.execute("PRAGMA foreign_keys=ON")


# ------------------------------------------------------------------------- Django's


@cache
def django_migrations() -> list[str]:
    """Django's migrations, in the order they apply."""
    graph = MigrationLoader(None, ignore_no_migrations=True).graph
    [leaf] = graph.leaf_nodes(APP)
    return [name for app, name in graph.forwards_plan(leaf) if app == APP]


def head() -> str:
    """The last of this version's migrations: Django's."""
    return django_migrations()[-1]


def _applied(db: Database) -> list[str]:
    """Django's migrations the database has had, in order; refused if it has had one this
    version doesn't know."""
    recorder = MigrationRecorder(connections[db.alias])
    applied = {name for app, name in recorder.applied_migrations() if app == APP}
    unknown = sorted(applied - set(django_migrations()))
    if unknown:
        raise SchemaError(_unknown(unknown[-1]))
    return [name for name in django_migrations() if name in applied]


@contextmanager
def _django(db: Database) -> Iterator[None]:
    """Django's connection to the database, closed (back to its pool) after."""
    try:
        yield
    finally:
        connections[db.alias].close()


# --------------------------------------------------------------------------- both


def _alembic(db: Database) -> tuple[str | None, bool]:
    """Alembic's revision of the database, and whether it was made before migrations."""
    with db.engine.connect() as connection:
        current = MigrationContext.configure(connection).get_current_revision()
        return current, current is None and _unversioned(connection)


def status(db: Database) -> Status:
    current, unversioned = _alembic(db)
    pending = _pending(current)
    with _django(db):
        applied = _applied(db)
    pending += [name for name in django_migrations() if name not in applied]
    return Status(
        current=applied[-1] if applied else current,
        head=head(),
        pending=pending,
        unversioned=unversioned,
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
def _one_at_a_time(engine: Engine) -> Iterator[None]:
    """Replicas starting together migrate one at a time (PostgreSQL)."""
    if engine.dialect.name != "postgresql":
        yield
        return
    with engine.connect() as connection:
        connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": _LOCK_KEY})
        connection.commit()
        try:
            yield
        finally:
            connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": _LOCK_KEY})
            connection.commit()


def upgrade(db: Database) -> list[str]:
    """Bring the schema up to date; returns the migrations applied, in order."""
    with _one_at_a_time(db.engine):
        with _migrating(db.engine) as connection:
            current = MigrationContext.configure(connection).get_current_revision()
            if current is None and _unversioned(connection):
                log.info("adopting a database created before migrations")
            applied = _pending(current)
            command.upgrade(_config(connection), "head")
        with _django(db):
            done = _applied(db)
            pending = [name for name in django_migrations() if name not in done]
            if pending:
                # The first, recorded as applied: Alembic's migrations built its tables.
                call_command(
                    "migrate",
                    APP,
                    database=db.alias,
                    fake_initial=True,
                    interactive=False,
                    verbosity=0,
                )
            applied += pending
    for step in applied:
        log.info("database migrated to %s", step)
    return applied


def upgrade_sql(db: Database) -> str:
    """The SQL that ``upgrade`` would run, for review by a database administrator.

    For a database from before migrations, the tables it lacks are created when it
    is adopted, which this leaves out.
    """
    state = status(db)
    if not state.pending:
        return ""
    output = io.StringIO()
    current, unversioned = _alembic(db)
    if _pending(current) or unversioned:
        start = BASELINE if unversioned else current
        target = f"{start}:head" if start else "head"
        command.upgrade(_config(output=output, dialect=db.engine.dialect.name), target, sql=True)
    django = [step for step in state.pending if step in django_migrations()]
    with _django(db):
        connection = connections[db.alias]
        recorder = MigrationRecorder(connection)
        if not recorder.has_table():
            with connection.schema_editor(collect_sql=True, atomic=False) as editor:
                editor.create_model(recorder.Migration)
            output.write("\n".join(editor.collected_sql) + "\n")
        loader = MigrationLoader(connection)
        for name in django:
            migration = loader.graph.nodes[(APP, name)]
            # The first is recorded only: Alembic's migrations built its tables.
            first = name == django_migrations()[0]
            statements = [] if first else loader.collect_sql([(migration, False)])
            statements.append(_recorded(name))
            # Each with its record, in one transaction, as migrate applies it.
            if migration.atomic and connection.features.can_rollback_ddl:
                ops = connection.ops
                statements = [ops.start_transaction_sql(), *statements, ops.end_transaction_sql()]
            output.write("\n".join(statements) + "\n")
    return output.getvalue()


def _recorded(name: str) -> str:
    """The statement that records Django's migration ``name``, one of this version's own,
    as applied."""
    values = f"'{APP}', '{name}', CURRENT_TIMESTAMP"
    return f"INSERT INTO django_migrations (app, name, applied) VALUES ({values});"  # noqa: S608
