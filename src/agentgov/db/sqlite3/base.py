"""Django's SQLite backend, as agentgov.db uses it: a connection goes back to a pool when a
transaction ends rather than closing, as Django's PostgreSQL backend does with psycopg's,
since opening one takes longer than most transactions."""

from __future__ import annotations

import queue
import threading
from typing import Any

from django.db.backends.sqlite3 import base


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


class DatabaseWrapper(base.DatabaseWrapper):
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
