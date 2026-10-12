"""Database engine and session management."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, create_engine, event, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator

log = logging.getLogger(__name__)

_CHANGED = "agentgov.changed"
# What a transaction writes last, just before it commits, after every other change it made
# (agentgov.ledger's entries: the chain's head is the last row a transaction locks).
WRITE_LAST: list[Callable[[Session], None]] = []


def lock(session: Session, instance: Any) -> None:
    """Lock ``instance``'s row until the transaction ends, and read it afresh: decisions on
    the same thing (two approvers deciding one request at once, say) take turns, and the
    later one sees the earlier one's outcome. Nothing to do on SQLite, where each write
    transaction holds the whole database."""
    if session.get_bind().dialect.name == "sqlite":
        return
    state = inspect(instance)
    if state.identity is None:
        return  # not in the database yet
    keys = state.mapper.primary_key
    where = [key == value for key, value in zip(keys, state.identity, strict=True)]
    session.execute(select(*keys).where(*where).with_for_update())
    session.refresh(instance)


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


# Constraint names as PostgreSQL gives them when none is set, so databases made before
# migrations existed and databases built by them name every constraint the same way.
NAMING_CONVENTION = {
    "pk": "%(table_name)s_pkey",
    "uq": "%(table_name)s_%(column_0_name)s_key",
    "fk": "%(table_name)s_%(column_0_name)s_fkey",
    "ix": "ix_%(column_0_label)s",
    "ck": "%(table_name)s_%(constraint_name)s_check",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


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


# TCP keepalives on every connection to PostgreSQL, both ways: the server drops a replica
# whose host vanished within half a minute, and with it the advisory locks it held (the
# leader's, a job's), and the replica notices as soon that it lost the server.
CLIENT_KEEPALIVES: dict[str, Any] = {
    "keepalives": 1,
    "keepalives_idle": 10,
    "keepalives_interval": 5,
    "keepalives_count": 3,
}
SERVER_KEEPALIVES = (
    "SET tcp_keepalives_idle = 10",
    "SET tcp_keepalives_interval = 5",
    "SET tcp_keepalives_count = 3",
)


def _configure_postgresql(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection: Any, _record: Any) -> None:
        # As statements rather than startup options, which poolers such as PgBouncer
        # refuse; committed, so that they last as long as the connection.
        with dbapi_connection.cursor() as cursor:
            for statement in SERVER_KEEPALIVES:
                cursor.execute(statement)
        dbapi_connection.commit()


class Database:
    def __init__(self, url: str, on_commit: Callable[[set[str]], None] | None = None) -> None:
        self.url = url
        self.on_commit = on_commit
        # Called with a transaction's topics just before it commits, inside it: how the
        # other replicas hear about them (agentgov.coordination).
        self.before_commit: Callable[[Session, set[str]], None] | None = None
        # What a transaction must pass to commit, checked inside it first: a job's still
        # holding its lock (agentgov.coordination).
        self.commit_checks: list[Callable[[Session], None]] = []
        kwargs: dict[str, Any] = {}
        is_sqlite = url.startswith("sqlite")
        in_memory = is_sqlite and (":memory:" in url or url.rstrip("/") == "sqlite:")
        if is_sqlite:
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
            if in_memory:
                kwargs["poolclass"] = StaticPool
        else:
            kwargs["pool_pre_ping"] = True
        postgresql = url.startswith("postgresql")
        if postgresql:
            kwargs["connect_args"] = dict(CLIENT_KEEPALIVES)
        self.engine = create_engine(url, **kwargs)
        if is_sqlite:
            _configure_sqlite(self.engine, in_memory)
        if postgresql:
            _configure_postgresql(self.engine)
        self._sessionmaker = sessionmaker(bind=self.engine, expire_on_commit=False)
        event.listen(self._sessionmaker, "before_commit", self._before_commit)
        event.listen(self._sessionmaker, "after_commit", self._after_commit)
        event.listen(self._sessionmaker, "after_rollback", self._after_rollback)

    def _before_commit(self, session: Session) -> None:
        for check in self.commit_checks:
            check(session)
        for write in WRITE_LAST:
            write(session)
        topics = session.info.get(_CHANGED)
        if topics and self.before_commit is not None:
            self.before_commit(session, set(topics))

    def _after_commit(self, session: Session) -> None:
        topics = session.info.pop(_CHANGED, None)
        if topics and self.on_commit is not None:
            try:
                self.on_commit(set(topics))
            except Exception:  # never let a notifier break a committed transaction
                log.exception("change notification failed for %s", sorted(topics))

    def _after_rollback(self, session: Session) -> None:
        session.info.pop(_CHANGED, None)

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
