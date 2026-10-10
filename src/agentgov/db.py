"""Database engine and session management."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator

log = logging.getLogger(__name__)

_CHANGED = "agentgov.changed"


def mark_changed(session: Session, *topics: str) -> None:
    """Record that this transaction changed registry state.

    Topics are delivered to ``Database.on_commit`` only after the transaction
    commits, so reconcilers never act on state that is later rolled back.
    """
    session.info.setdefault(_CHANGED, set()).update(topics)


class UTCDateTime(TypeDecorator):
    """Stores naive UTC timestamps and always returns timezone-aware UTC datetimes.

    SQLite has no native timezone support, so normalising here keeps comparisons
    consistent across SQLite and PostgreSQL.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    pass


def _configure_sqlite(engine: Engine, in_memory: bool) -> None:
    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection: Any, _record: Any) -> None:
        # Let SQLAlchemy (not pysqlite) control transaction boundaries so we can
        # issue BEGIN IMMEDIATE below.
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        if not in_memory:
            cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _on_begin(connection: Any) -> None:
        # Serialise writers up front. Deferred transactions in WAL mode fail with
        # SQLITE_BUSY_SNAPSHOT when they upgrade from reader to writer after a
        # concurrent commit; BEGIN IMMEDIATE avoids that class of error entirely.
        connection.exec_driver_sql("BEGIN IMMEDIATE")


class Database:
    def __init__(self, url: str, on_commit: Callable[[set[str]], None] | None = None) -> None:
        self.url = url
        self.on_commit = on_commit
        kwargs: dict[str, Any] = {}
        is_sqlite = url.startswith("sqlite")
        in_memory = is_sqlite and (":memory:" in url or url.rstrip("/") == "sqlite:")
        if is_sqlite:
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
            if in_memory:
                kwargs["poolclass"] = StaticPool
        else:
            kwargs["pool_pre_ping"] = True
        self.engine = create_engine(url, **kwargs)
        if is_sqlite:
            _configure_sqlite(self.engine, in_memory)
        self._sessionmaker = sessionmaker(bind=self.engine, expire_on_commit=False)
        event.listen(self._sessionmaker, "after_commit", self._after_commit)
        event.listen(self._sessionmaker, "after_rollback", self._after_rollback)

    def _after_commit(self, session: Session) -> None:
        topics = session.info.pop(_CHANGED, None)
        if topics and self.on_commit is not None:
            try:
                self.on_commit(set(topics))
            except Exception:  # never let a notifier break a committed transaction
                log.exception("change notification failed for %s", sorted(topics))

    def _after_rollback(self, session: Session) -> None:
        session.info.pop(_CHANGED, None)

    def create_all(self) -> None:
        from agentgov import models  # noqa: F401  (register mappers)

        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._sessionmaker()
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:
        self.engine.dispose()
