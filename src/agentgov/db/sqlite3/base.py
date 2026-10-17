"""Django's SQLite backend, as agentgov.db uses it: a connection goes back to a pool when a
transaction ends rather than closing, as Django's PostgreSQL backend does with psycopg's,
since opening one takes longer than most transactions; and foreign keys with their rules on
delete (agentgov.db.keys)."""

from __future__ import annotations

import queue
import re
import threading
from typing import Any

from django.db.backends.sqlite3 import base, schema

from agentgov.db import keys


class Pool:
    """The open connections to one database, for whichever thread transacts next."""

    def __init__(self, size: int) -> None:
        self._idle: queue.LifoQueue[Any] = queue.LifoQueue(maxsize=size)
        self._closed = False
        self._lock = threading.Lock()

    def get(self) -> Any | None:
        try:
            return self._idle.get_nowait()
        except queue.Empty:
            return None

    def put(self, connection: Any) -> None:
        with self._lock:
            if not self._closed:
                try:
                    self._idle.put_nowait(connection)
                    return
                except queue.Full:
                    pass
        connection.close()

    def close(self) -> None:
        with self._lock:
            self._closed = True
        while (connection := self.get()) is not None:
            connection.close()


# By Django's name for each database (agentgov.db opens and closes them).
POOLS: dict[str, Pool] = {}


class DatabaseSchemaEditor(keys.KeyRules, schema.DatabaseSchemaEditor):
    def table_sql(self, model: Any) -> tuple[str, Any]:
        # SQLite takes a table's keys only as the table is made: each is written at the end of
        # its column's definition, and its rule goes into it.
        sql, params = super().table_sql(model)
        for field in model._meta.local_fields:
            ruled = keys.rule_sql(field)
            if not ruled:
                continue
            key = self.sql_create_inline_fk % {
                "to_table": self.quote_name(field.target_field.model._meta.db_table),
                "to_column": self.quote_name(field.target_field.column),
            }
            column = re.search(rf"(?:\(|, ){re.escape(self.quote_name(field.column))} ", sql)
            assert column is not None, field.column
            at = sql.index(key, column.end())
            sql = sql[:at] + keys.with_rule(key, ruled) + sql[at + len(key) :]
        return sql, params


class DatabaseWrapper(base.DatabaseWrapper):
    SchemaEditorClass = DatabaseSchemaEditor

    def get_new_connection(self, conn_params: dict[str, Any]) -> Any:
        pool = POOLS.get(self.alias)
        connection = pool.get() if pool is not None else None
        if connection is not None:
            return connection
        return super().get_new_connection(conn_params)

    def _close(self) -> None:
        pool = POOLS.get(self.alias)
        connection = self.connection
        # One still in a transaction (a failure part way) is closed, never shared.
        if pool is None or connection is None or connection.in_transaction:
            super()._close()
            return
        pool.put(connection)
