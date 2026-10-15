"""The rules every transaction keeps, now that Django runs them (agentgov.db,
docs/adr/0007-django.md): on SQLite, and on PostgreSQL where the tests run there."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest
from django.db import IntegrityError, connections
from sqlalchemy import event, select

from agentgov import ledger
from agentgov.db import Database, Transaction, mark_changed, transaction_of
from agentgov.models import IntegrationState

WHEN = "2026-10-15 00:00:00.000000"


def put(tx: Transaction, key: str) -> None:
    """A row written by Django, on the transaction's connection."""
    tx.execute(
        "INSERT INTO integration_state (key, data, updated_at) VALUES (%s, %s, %s)",
        [key, "{}", WHEN],
    )


def keys(db: Database) -> list[str]:
    with db.transaction() as tx:
        return [key for (key,) in tx.execute("SELECT key FROM integration_state ORDER BY key")]


def what(sql: str) -> str:
    """What a statement does, and to which table: "INSERT ledger"."""
    words = sql.split()
    verb = words[0].upper()
    return f"{verb} {words[2] if verb in ('INSERT', 'DELETE') else words[1]}"


def entries(db: Database) -> list[str]:
    with db.transaction() as tx:
        return [type_ for (type_,) in tx.execute("SELECT type FROM ledger ORDER BY seq")]


@pytest.fixture
def heard() -> list[set[str]]:
    return []


@pytest.fixture
def db(database_url: str, heard: list[set[str]]) -> Database:
    return Database(database_url, on_commit=heard.append)


def test_what_django_and_sqlalchemy_write_commits_together(db: Database) -> None:
    with db.transaction() as tx:
        tx.orm().add(IntegrationState(key="by-sqlalchemy", data={}))
        put(tx, "by-django")
        # Each sees what the other wrote: one connection, one transaction.
        assert tx.orm().get(IntegrationState, "by-django") is not None
    assert keys(db) == ["by-django", "by-sqlalchemy"]


def test_what_both_write_rolls_back_together(db: Database, heard: list[set[str]]) -> None:
    with pytest.raises(RuntimeError), db.session() as s:
        s.add(IntegrationState(key="by-sqlalchemy", data={}))
        put(transaction_of(s), "by-django")
        ledger.append(s, type="test.rolled-back", actor="tests")
        raise RuntimeError("the request failed")
    assert keys(db) == []
    assert entries(db) == []
    assert heard == []


def test_a_savepoint_rolls_back_alone(db: Database) -> None:
    with db.transaction() as tx:
        put(tx, "before")
        ledger.append(tx, type="test.kept", actor="tests")
        with pytest.raises(RuntimeError), db.transaction() as inner:
            assert inner is tx  # the same transaction, in part
            put(tx, "in-savepoint")
            tx.orm().add(IntegrationState(key="in-savepoint-too", data={}))
            ledger.append(tx, type="test.rolled-back", actor="tests")
            raise RuntimeError("this part failed")
        put(tx, "after")
        ledger.append(tx, type="test.kept-too", actor="tests")
    assert keys(db) == ["after", "before"]
    assert entries(db) == ["test.kept", "test.kept-too"]


def test_ledger_entries_are_written_last(db: Database) -> None:
    statements: list[str] = []

    def heard_sqlalchemy(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
        statements.append(what(statement))

    def heard_django(execute: Any, sql: str, params: Any, many: bool, context: Any) -> Any:
        statements.append(what(sql))
        return execute(sql, params, many, context)

    event.listen(db._lent, "before_cursor_execute", heard_sqlalchemy)
    with db.transaction() as tx, connections[db.alias].execute_wrapper(heard_django):
        ledger.append(tx, type="test.first", actor="tests")
        # Not written yet: the transaction's own queries don't see it.
        assert tx.execute("SELECT count(*) FROM ledger") == [(0,)]
        put(tx, "written-after-the-entry-was-appended")
    # The chain's head is the last row the transaction locked, after everything else it
    # wrote: two transactions that lock the same rows can't deadlock over it.
    writes = [s for s in statements if s.split()[0] in ("INSERT", "UPDATE", "DELETE")]
    assert writes[0] == "INSERT integration_state"
    assert "INSERT ledger" in writes
    assert {s.split()[1] for s in writes[1:]} == {"ledger", "ledger_head"}
    assert entries(db) == ["test.first"]


def test_changes_are_heard_once_committed_never_before(db: Database, heard: list[set[str]]) -> None:
    with db.transaction() as tx:
        mark_changed(tx, "agents")
        put(tx, "x")
        assert heard == []  # not while it may still roll back
    assert heard == [{"agents"}]
    with pytest.raises(RuntimeError), db.transaction() as tx:
        mark_changed(tx, "toolservers")
        raise RuntimeError("rolled back")
    assert heard == [{"agents"}]


def test_a_commit_that_fails_is_never_heard(db: Database, heard: list[set[str]]) -> None:
    # A constraint checked only as the transaction commits, which it breaks.
    with pytest.raises(IntegrityError), db.transaction() as tx:
        mark_changed(tx, "agents")
        put(tx, "x")
        if db.sqlite:
            tx.execute("CREATE TEMP TABLE parent (id INTEGER PRIMARY KEY)")
            tx.execute(
                "CREATE TEMP TABLE child (parent INTEGER REFERENCES parent (id) "
                "DEFERRABLE INITIALLY DEFERRED)"
            )
            tx.execute("INSERT INTO child VALUES (1)")
        else:
            tx.execute(
                "CREATE TEMP TABLE twice (id INTEGER, UNIQUE (id) DEFERRABLE INITIALLY "
                "DEFERRED) ON COMMIT DROP"
            )
            tx.execute("INSERT INTO twice VALUES (1), (1)")
    assert heard == []
    assert keys(db) == []


def test_a_transaction_commits_only_past_its_checks(db: Database, heard: list[set[str]]) -> None:
    told: list[set[str]] = []
    db.before_commit = lambda tx, topics: told.append(topics)

    def refuse(tx: Transaction) -> None:
        raise RuntimeError("the job lost its lock")

    db.commit_checks.append(refuse)
    with pytest.raises(RuntimeError, match="lost its lock"), db.transaction() as tx:
        put(tx, "x")
        ledger.append(tx, type="test.never", actor="tests")
        mark_changed(tx, "agents")
    db.commit_checks.remove(refuse)
    assert keys(db) == []
    assert entries(db) == []
    assert heard == [] and told == []


def test_a_session_works_only_in_its_transaction(db: Database) -> None:
    with db.session() as s:
        s.add(IntegrationState(key="x", data={}))
    with pytest.raises(RuntimeError, match="outside its transaction"):
        s.execute(select(IntegrationState))


def test_each_transaction_gives_its_connection_back(db: Database) -> None:
    def transact() -> None:
        for _ in range(5):
            with db.transaction() as tx:
                tx.execute("SELECT 1")
            assert connections[db.alias].connection is None

    threads = [threading.Thread(target=transact) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    transact()


def test_sqlite_writers_take_their_lock_up_front(db: Database) -> None:
    if not db.sqlite:
        pytest.skip("PostgreSQL locks rows, not the database")
    order: list[str] = []

    def second() -> None:
        with db.transaction():
            order.append("second began")

    with db.transaction():
        order.append("first began")
        other = threading.Thread(target=second)
        other.start()
        time.sleep(0.3)
        order.append("first ends")
    other.join()
    assert order == ["first began", "first ends", "second began"]


def test_disposing_closes_the_connections(db: Database) -> None:
    with db.transaction() as tx:
        put(tx, "x")
    db.dispose()
    assert db.alias not in connections.settings
    with pytest.raises(Exception, match=db.alias):
        connections[db.alias].ensure_connection()


def test_a_connection_the_server_dropped_is_replaced(db: Database) -> None:
    if db.sqlite:
        pytest.skip("SQLite has no server to drop a connection")
    with db.transaction() as tx:
        [(pid,)] = tx.execute("SELECT pg_backend_pid()")
    # The server drops it while it waits in the pool, as it does when it restarts.
    with db.engine.connect() as other:
        other.exec_driver_sql(f"SELECT pg_terminate_backend({int(pid)})")
    with db.transaction() as tx:
        assert tx.execute("SELECT 1") == [(1,)]
