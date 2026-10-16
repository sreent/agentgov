"""Alembic's environment for AgentGov's schema (see agentgov.migrations)."""

from __future__ import annotations

from typing import Any

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection

from agentgov.models import Base, UTCDateTime

config = context.config


def _render_item(kind: str, obj: Any, _autogen: Any) -> str | bool:
    # The database holds plain timestamps; UTCDateTime only converts them in Python.
    if kind == "type" and isinstance(obj, UTCDateTime):
        return "sa.DateTime()"
    return False


def _skip_empty(_context: Any, _revision: Any, directives: list[Any]) -> None:
    # scripts/new-migration.sh writes nothing when the models haven't changed.
    if config.attributes.get("skip_empty") and directives[0].upgrade_ops.is_empty():
        directives[:] = []


def _options(dialect: str) -> dict[str, Any]:
    return {
        "target_metadata": Base.metadata,
        # SQLite alters a table by rebuilding it.
        "render_as_batch": dialect == "sqlite",
        "compare_type": True,
        "render_item": _render_item,
        "process_revision_directives": _skip_empty,
    }


def _online(connection: Connection) -> None:
    context.configure(connection=connection, **_options(connection.dialect.name))
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    # `agentgov db upgrade --sql`: the statements, for a database administrator.
    dialect = config.attributes.get("dialect", "postgresql")
    context.configure(dialect_name=dialect, literal_binds=True, **_options(dialect))
    with context.begin_transaction():
        context.run_migrations()
elif (connection := config.attributes.get("connection")) is not None:
    _online(connection)
else:
    # `alembic` run by hand with sqlalchemy.url set.
    with create_engine(config.get_main_option("sqlalchemy.url")).begin() as connection:
        _online(connection)
