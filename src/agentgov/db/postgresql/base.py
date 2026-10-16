"""Django's PostgreSQL backend, as agentgov.db uses it: TCP keepalives on the server's side
of every connection too, as on the client's; and the schema's indexes, no others."""

from __future__ import annotations

from typing import Any

from django.db.backends.postgresql import base, schema

from agentgov.db import SERVER_KEEPALIVES


class DatabaseSchemaEditor(schema.DatabaseSchemaEditor):
    """No second index (``varchar_pattern_ops``) on each key and indexed text column, which
    Django adds for ``LIKE``: the schema has the indexes its migrations name, as Alembic's
    built it."""

    def _create_like_index_sql(self, model: Any, field: Any) -> None:
        return None


class DatabaseWrapper(base.DatabaseWrapper):
    SchemaEditorClass = DatabaseSchemaEditor

    def _configure_connection(self, connection: Any) -> bool:
        # Once per connection, as psycopg's pool opens it: as statements rather than
        # startup options, which poolers such as PgBouncer refuse.
        with connection.cursor() as cursor:
            for statement in SERVER_KEEPALIVES:
                cursor.execute(statement)
        super()._configure_connection(connection)
        return True
