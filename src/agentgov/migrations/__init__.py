"""The database schema's history, as Alembic migrations.

The control plane brings its database up to date when it starts
(``AGENTGOV_DATABASE_AUTO_MIGRATE``, on by default), and ``agentgov db upgrade``
does the same by hand, for example from a deployment job that runs before
the new version starts. Migrations live in ``versions/``, one per change.

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
from typing import Any

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.script.revision import RevisionError
from alembic.util import CommandError
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection, Engine

log = logging.getLogger(__name__)

LOCATION = Path(__file__).parent
# The schema that create_all built when migrations were introduced.
BASELINE = "0001"
# Tables every AgentGov database has had: one of them without a version table
# means a database from before migrations.
_PRE_MIGRATION_TABLES = {"agents", "blueprints", "ledger"}
# PostgreSQL advisory lock taken while migrating, so replicas starting together
# migrate one at a time ("AGMG").
_LOCK_KEY = 0x41474D47


class SchemaError(RuntimeError):
    """The database's schema is not the one this version of AgentGov needs."""


@dataclass(frozen=True)
class Status:
    current: str | None
    head: str
    pending: list[str]
    # Created by create_all before AgentGov had migrations; adopted on upgrade.
    unversioned: bool = False

    @property
    def up_to_date(self) -> bool:
        return not self.pending and not self.unversioned


@cache
def scripts() -> ScriptDirectory:
    return ScriptDirectory(str(LOCATION))


def head() -> str:
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
    """Revisions between ``current`` and head, oldest first."""
    try:
        steps = list(scripts().iterate_revisions(head(), current))
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


def status(engine: Engine) -> Status:
    with engine.connect() as connection:
        current = MigrationContext.configure(connection).get_current_revision()
        unversioned = current is None and _unversioned(connection)
    return Status(current=current, head=head(), pending=_pending(current), unversioned=unversioned)


def check(engine: Engine) -> None:
    """Raise SchemaError unless the schema is the one this version needs."""
    state = status(engine)
    if not state.up_to_date:
        raise SchemaError(
            f"the database's schema is at revision {state.current or 'none'} but this version "
            f"of AgentGov needs {state.head}: run `agentgov db upgrade`, or set "
            "AGENTGOV_DATABASE_AUTO_MIGRATE=true"
        )


@contextmanager
def _migrating(engine: Engine) -> Iterator[Connection]:
    """A connection in a transaction, for one migrator at a time."""
    with engine.connect() as connection:
        sqlite = connection.dialect.name == "sqlite"
        if sqlite:
            # SQLite alters a table by rebuilding it, which trips foreign keys; the
            # setting only takes effect outside a transaction.
            connection.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
        try:
            with connection.begin():
                if connection.dialect.name == "postgresql":
                    connection.execute(
                        text("SELECT pg_advisory_xact_lock(:key)"), {"key": _LOCK_KEY}
                    )
                yield connection
        finally:
            if sqlite:
                connection.connection.dbapi_connection.execute("PRAGMA foreign_keys=ON")


def upgrade(engine: Engine) -> list[str]:
    """Bring the schema up to date; returns the migrations applied, in order."""
    with _migrating(engine) as connection:
        current = MigrationContext.configure(connection).get_current_revision()
        if current is None and _unversioned(connection):
            log.info("adopting a database created before migrations")
        applied = _pending(current)
        command.upgrade(_config(connection), "head")
    for step in applied:
        log.info("database migrated to %s", step)
    return applied


def upgrade_sql(engine: Engine) -> str:
    """The SQL that ``upgrade`` would run, for review by a database administrator.

    For a database from before migrations, the tables it lacks are created when it
    is adopted, which this leaves out.
    """
    state = status(engine)
    if not state.pending:
        return ""
    start = BASELINE if state.unversioned else state.current
    output = io.StringIO()
    target = f"{start}:head" if start else "head"
    command.upgrade(_config(output=output, dialect=engine.dialect.name), target, sql=True)
    return output.getvalue()
