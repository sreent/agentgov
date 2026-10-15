"""The database: its connections and transactions, which Django runs (docs/adr/0007-django.md),
and the SQLAlchemy models and sessions that the modules use until they move to Django's ORM.

``Database.transaction()`` is one of Django's atomic blocks on the database, with the rules
every transaction keeps (``Transaction``): checks it must pass before it commits, the ledger's
entries written last, and its changes announced once it commits, never before. Nested, it is
a savepoint. ``Database.session()`` is the same transaction with a SQLAlchemy session in it, on
Django's connection: what either writes commits, or rolls back, with what the other wrote.

Django's ORM uses the database whose transaction is open (``Router``), and sees what the
session changed: the session writes it first, as it does before its own queries. The
session doesn't see what Django's ORM changed in rows it already loaded, until it loads them
again: a module that moved to Django's ORM doesn't change what one still on SQLAlchemy holds,
nor hands it Django's objects to change.
"""

from __future__ import annotations

import itertools
import logging
import re
import shutil
import tempfile
import threading
import weakref
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from django.db import DEFAULT_DB_ALIAS, connections
from django.db import transaction as django_transaction
from sqlalchemy import DateTime, MetaData, create_engine, event, inspect, select
from sqlalchemy.dialects import registry
from sqlalchemy.dialects.postgresql.psycopg import PGDialect_psycopg
from sqlalchemy.dialects.sqlite.pysqlite import SQLiteDialect_pysqlite
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy.types import TypeDecorator

from agentgov import web

# Django's settings, before anything imports the models (agentgov.db.models).
web.configure()

log = logging.getLogger(__name__)

# What a transaction writes last, just before it commits, after every other change it made
# (agentgov.ledger's entries: the chain's head is the last row a transaction locks).
WRITE_LAST: list[Callable[[Transaction], None]] = []
# What keeps track of a part of a transaction that may roll back alone (a savepoint): each
# is called as one begins, and returns what to undo if it rolls back (agentgov.ledger's
# entries appended in it go with it).
SAVEPOINTS: list[Callable[[Transaction], Callable[[], None]]] = []
# Where a SQLAlchemy session keeps the transaction it is in.
_TRANSACTION = "agentgov.transaction"
# Connections open at once, by each process, to a PostgreSQL database: as many as SQLAlchemy's
# pool allowed (5, and 10 more when busy).
POOL_SIZE = 15


class Transaction:
    """A transaction on a database, open in this thread: what it changed, and what the
    modules keep with it until it commits."""

    def __init__(self, database: Database) -> None:
        self.database = database
        # What changed, for those acting on it once it commits (Database.on_commit).
        self.topics: set[str] = set()
        # What the modules keep until the commit (agentgov.ledger's entries).
        self.info: dict[str, Any] = {}
        self._session: Session | None = None

    def orm(self) -> Session:
        """The SQLAlchemy session in this transaction, made the first time it is asked for."""
        if self._session is None:
            self._session = self.database._sessions(info={_TRANSACTION: self})
        return self._session

    def flush(self) -> None:
        """What the SQLAlchemy session holds, written: before anything else reads it."""
        if self._session is not None:
            self._session.flush()

    def execute(self, sql: str, params: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
        """``sql`` (``%s`` for each parameter) in this transaction: the rows it returns."""
        self.flush()
        with connections[self.database.alias].cursor() as cursor:
            cursor.execute(sql, params)
            return list(cursor.fetchall()) if cursor.description else []

    @contextmanager
    def savepoint(self) -> Iterator[None]:
        """A part of this transaction that rolls back alone when it fails."""
        self.flush()
        undo = [mark(self) for mark in SAVEPOINTS]
        try:
            with django_transaction.atomic(using=self.database.alias):
                yield
                self.flush()
        except BaseException:
            for step in reversed(undo):
                step()
            if self._session is not None:
                # The session forgets what it wrote in the part rolled back, and reads what
                # it loaded before again.
                self._session.rollback()
            raise

    def _close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None


# What the modules' functions take for the transaction they run in: the transaction, or,
# from the modules still on SQLAlchemy, its session (Database.session).
Where = Transaction | Session


def transaction_of(where: Where) -> Transaction:
    """The transaction a session is in (Database.session)."""
    if isinstance(where, Transaction):
        return where
    found = where.info.get(_TRANSACTION)
    if found is None:
        raise RuntimeError("a session that isn't one of Database.session()'s")
    return found


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


def mark_changed(where: Where, *topics: str) -> None:
    """Record that this transaction changed registry state.

    Topics are delivered to ``Database.on_commit`` only after the transaction
    commits, so reconcilers never act on state that is later rolled back.
    """
    transaction_of(where).topics.update(topics)


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


def _configure_sqlite(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection: Any, _record: Any) -> None:
        # Let SQLAlchemy (not pysqlite) control transaction boundaries so we can
        # issue BEGIN IMMEDIATE below.
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
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


# ------------------------------------------------- SQLAlchemy on Django's connections


class _Lent:
    """Django's connection, as a session in Database.session() sees it: Django commits,
    rolls back and closes it, so those do nothing here."""

    __slots__ = ("_connection",)

    def __init__(self, connection: Any) -> None:
        object.__setattr__(self, "_connection", connection)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._connection, name, value)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass


class _LentPostgreSQL(PGDialect_psycopg):
    """psycopg's dialect, on a connection Django lent: it adds nothing to the connection, as
    it does to one of its own (a handler for the server's notices, each time it is lent)."""

    supports_statement_cache = True

    def on_connect(self) -> None:  # type: ignore[override]
        return None


class _LentSQLite(SQLiteDialect_pysqlite):
    supports_statement_cache = True

    def on_connect(self) -> None:  # type: ignore[override]
        return None


registry.register("postgresql.agentgov", __name__, "_LentPostgreSQL")
registry.register("sqlite.agentgov", __name__, "_LentSQLite")


# Statements that read or write the tables, as Django's ORM runs them.
_READS_OR_WRITES = re.compile(r"\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b", re.IGNORECASE)


def _autoflush(
    tx: Transaction, execute: Callable[..., Any], sql: Any, params: Any, many: bool, context: Any
) -> Any:
    """What the transaction's SQLAlchemy session holds, written before Django runs a
    statement that reads or writes the tables, as SQLAlchemy does before its own queries
    (and doesn't in its ``no_autoflush`` blocks). Not before Django's savepoint statements:
    rolling one back must not fail on what was changed in it."""
    session = tx._session
    if session is not None and isinstance(sql, str) and _READS_OR_WRITES.match(sql):
        session._autoflush()
    return execute(sql, params, many, context)


# ------------------------------------------------------------------- the databases

_names = itertools.count(1)
# Databases disposed of: each thread forgets its connection handlers for them in time.
_DISPOSED: set[str] = set()
_threads = threading.local()
_LIVE: weakref.WeakSet[Database] = weakref.WeakSet()


class Router:
    """Django's ORM on the database whose transaction is open in this thread
    (Database.transaction): the models name no database of their own, and are used only
    in a transaction."""

    def db_for_read(self, model: Any, **hints: Any) -> str:
        return _open_alias()

    def db_for_write(self, model: Any, **hints: Any) -> str:
        return _open_alias()

    def allow_relation(self, a: Any, b: Any, **hints: Any) -> bool:
        return True


def _open_alias() -> str:
    open_: list[str] | None = getattr(_threads, "open", None)
    if not open_:
        raise RuntimeError("Django's models are used in a transaction (Database.transaction)")
    return open_[-1]


def _forget_disposed() -> None:
    """This thread's Django connection handlers for databases since disposed of."""
    seen: set[str] | None = getattr(_threads, "aliases", None)
    if not seen:
        return
    for alias in seen & _DISPOSED:
        with suppress(AttributeError):
            del connections[alias]
        seen.discard(alias)


def _django_database(url: str) -> tuple[dict[str, Any], Path | None]:
    """Django's settings for the database at ``url`` (as AGENTGOV_DATABASE_URL names it), and
    a directory made for it, to remove with it."""
    parsed = make_url(url)
    backend = parsed.get_backend_name()
    if backend == "sqlite":
        name, scratch = parsed.database, None
        if not name or name == ":memory:":
            # A database for this process only: a file of its own, removed with it, since
            # every connection here must see the same database (and in memory, each sees
            # one of its own).
            scratch = Path(tempfile.mkdtemp(prefix="agentgov-"))
            name = str(scratch / "agentgov.db")
        options = {
            "timeout": 30,
            # Serialise writers up front. Deferred transactions in WAL mode fail with
            # SQLITE_BUSY_SNAPSHOT when they upgrade from reader to writer after a
            # concurrent commit; BEGIN IMMEDIATE avoids that class of error entirely.
            "transaction_mode": "IMMEDIATE",
            "init_command": "PRAGMA journal_mode=WAL",
            # Timestamps as text, which the SQLAlchemy models read themselves.
            "detect_types": 0,
        }
        return {"ENGINE": "agentgov.db.sqlite3", "NAME": name, "OPTIONS": options}, scratch
    if backend == "postgresql":
        options: dict[str, Any] = dict(CLIENT_KEEPALIVES)
        options.update(parsed.query)
        options["pool"] = {"min_size": 0, "max_size": POOL_SIZE, "timeout": 30}
        return {
            "ENGINE": "agentgov.db.postgresql",
            "NAME": parsed.database or "",
            "USER": parsed.username or "",
            "PASSWORD": parsed.password or "",
            "HOST": parsed.host or "",
            "PORT": str(parsed.port or ""),
            "OPTIONS": options,
            # A connection the server dropped while it waited in the pool (a restart) is
            # replaced as it is taken, as SQLAlchemy's pre-ping did.
            "CONN_HEALTH_CHECKS": True,
        }, None
    raise ValueError(f"AgentGov runs on SQLite or PostgreSQL, not {backend}")


class Database:
    def __init__(self, url: str, on_commit: Callable[[set[str]], None] | None = None) -> None:
        self.url = url
        self.on_commit = on_commit
        # Called with a transaction's topics just before it commits, inside it: how the
        # other replicas hear about them (agentgov.coordination).
        self.before_commit: Callable[[Transaction, set[str]], None] | None = None
        # What a transaction must pass to commit, checked inside it first: a job's still
        # holding its lock (agentgov.coordination).
        self.commit_checks: list[Callable[[Transaction], None]] = []
        # Django's name for the database's connections, one per database here: a process
        # can hold several (the tests do).
        self.alias = f"agentgov-{next(_names)}"
        django, self._scratch = _django_database(url)
        here = make_url(url)
        if self._scratch is not None:
            here = here.set(database=django["NAME"])
        self.sqlite = here.get_backend_name() == "sqlite"
        self._local = threading.local()

        # SQLAlchemy's own connections, for what runs outside the transactions: the
        # migrations, and the coordinator's (agentgov.coordination).
        kwargs: dict[str, Any] = {}
        if self.sqlite:
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        else:
            kwargs["pool_pre_ping"] = True
            kwargs["connect_args"] = dict(CLIENT_KEEPALIVES)
        self.engine = create_engine(here, **kwargs)
        if self.sqlite:
            _configure_sqlite(self.engine)
        else:
            _configure_postgresql(self.engine)

        connections.settings[self.alias] = connections.configure_settings(
            {DEFAULT_DB_ALIAS: {}, self.alias: django}
        )[self.alias]
        if self.sqlite:
            from agentgov.db.sqlite3.base import POOLS, Pool

            POOLS[self.alias] = Pool(POOL_SIZE)
        # The sessions in Database.session(), on the connection Django has open for it.
        lent = here.set(drivername=f"{here.get_backend_name()}+agentgov")
        extra = {} if self.sqlite else {"use_native_hstore": False}
        self._lent = create_engine(
            lent, creator=self._lend, poolclass=NullPool, pool_reset_on_return=None, **extra
        )
        self._sessions = sessionmaker(bind=self._lent, expire_on_commit=False)
        _LIVE.add(self)

    def _lend(self) -> _Lent:
        connection = connections[self.alias]
        if not connection.in_atomic_block:
            raise RuntimeError("a database session used outside its transaction")
        connection.ensure_connection()
        return _Lent(connection.connection)

    @contextmanager
    def transaction(self) -> Iterator[Transaction]:
        """A transaction (a savepoint, within one), which commits when the block ends
        without an exception."""
        open_: Transaction | None = getattr(self._local, "transaction", None)
        if open_ is not None:
            with open_.savepoint():
                yield open_
            return
        _forget_disposed()
        seen: set[str] | None = getattr(_threads, "aliases", None)
        if seen is None:
            seen = _threads.aliases = set()
        seen.add(self.alias)
        open_: list[str] | None = getattr(_threads, "open", None)
        if open_ is None:
            open_ = _threads.open = []
        open_.append(self.alias)
        tx = self._local.transaction = Transaction(self)
        try:
            with (
                connections[self.alias].execute_wrapper(partial(_autoflush, tx)),
                django_transaction.atomic(using=self.alias),
            ):
                yield tx
                self._before_commit(tx)
        finally:
            open_.pop()
            self._local.transaction = None
            tx._close()
            self._release()

    @contextmanager
    def session(self) -> Iterator[Session]:
        """A transaction, as a SQLAlchemy session."""
        with self.transaction() as tx:
            yield tx.orm()

    def _before_commit(self, tx: Transaction) -> None:
        tx.flush()
        for check in self.commit_checks:
            check(tx)
        for write in WRITE_LAST:
            write(tx)
        tx.flush()
        if not tx.topics:
            return
        topics = set(tx.topics)
        if self.before_commit is not None:
            self.before_commit(tx, topics)
        if self.on_commit is not None:
            django_transaction.on_commit(partial(self._committed, topics), using=self.alias)

    def _committed(self, topics: set[str]) -> None:
        assert self.on_commit is not None
        try:
            self.on_commit(topics)
        except Exception:  # never let a notifier break a committed transaction
            log.exception("change notification failed for %s", sorted(topics))

    def _release(self) -> None:
        """This thread's connection, back to the pool for the next transaction."""
        connection = connections[self.alias]
        if connection.connection is None:
            return  # none opened (the transaction couldn't begin)
        try:
            connection.close()
        except Exception:
            log.exception("closing a connection to the database failed")

    def dispose(self) -> None:
        if self.alias in _DISPOSED:
            return
        _DISPOSED.add(self.alias)
        _forget_disposed()
        if self.sqlite:
            from agentgov.db.sqlite3.base import POOLS

            pool = POOLS.pop(self.alias, None)
            if pool is not None:
                pool.close()
        else:
            from django.db.backends.postgresql.base import DatabaseWrapper

            psycopg_pool = DatabaseWrapper._connection_pools.pop(self.alias, None)
            if psycopg_pool is not None:
                psycopg_pool.close()
        connections.settings.pop(self.alias, None)
        self._lent.dispose()
        self.engine.dispose()
        if self._scratch is not None:
            shutil.rmtree(self._scratch, ignore_errors=True)


def live() -> list[Database]:
    """The databases not yet disposed of (for the tests, which dispose of what each opened)."""
    return [db for db in list(_LIVE) if db.alias not in _DISPOSED]
