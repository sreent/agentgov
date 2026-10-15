"""Django's PostgreSQL backend, as agentgov.db uses it: TCP keepalives on the server's side
of every connection too, as on the client's."""

from __future__ import annotations

from typing import Any

from django.db.backends.postgresql import base

from agentgov.db import SERVER_KEEPALIVES


class DatabaseWrapper(base.DatabaseWrapper):
    def _configure_connection(self, connection: Any) -> bool:
        # Once per connection, as psycopg's pool opens it: as statements rather than
        # startup options, which poolers such as PgBouncer refuse.
        with connection.cursor() as cursor:
            for statement in SERVER_KEEPALIVES:
                cursor.execute(statement)
        super()._configure_connection(connection)
        return True
