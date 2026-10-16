"""Alembic's environment for AgentGov's schema (see agentgov.migrations): its migrations run
up to their last, and new ones are Django's (docs/adr/0007-django.md)."""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection

config = context.config


def _online(connection: Connection) -> None:
    context.configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    # `agentgov db upgrade --sql`: the statements, for a database administrator.
    dialect = config.attributes.get("dialect", "postgresql")
    context.configure(dialect_name=dialect, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
elif (connection := config.attributes.get("connection")) is not None:
    _online(connection)
else:
    # `alembic` run by hand with sqlalchemy.url set.
    with create_engine(config.get_main_option("sqlalchemy.url")).begin() as connection:
        _online(connection)
