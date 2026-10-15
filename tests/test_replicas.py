"""Several control-plane replicas on one database (agentgov.coordination).

The tests marked ``postgres`` run with AGENTGOV_TEST_POSTGRES_URL (scripts/ci.sh --postgres):
replicas coordinate through PostgreSQL, and SQLite has one process only.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from sqlalchemy import select, text

from agentgov import ledger
from agentgov.config import Settings
from agentgov.coordination import LOCK_SPACE, Coordinator, JobBusy, JobLost, lock_key
from agentgov.db import Database, mark_changed
from agentgov.models import LedgerEntry
from agentgov.registry import agents
from agentgov.runtime import Runtime
from agentgov.web import evidence as evidence_routes
from tests.conftest import ADMIN, POSTGRES

postgres = pytest.mark.skipif(not POSTGRES, reason="needs AGENTGOV_TEST_POSTGRES_URL")


def until(check: Callable[[], Any], timeout: float = 10.0) -> Any:
    """Wait for ``check`` to return something true; fail after ``timeout`` seconds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError(f"not within {timeout} seconds")


# -------------------------------------------------------------------------- SQLite


def test_one_process_leads_on_sqlite(settings: Settings) -> None:
    rt = Runtime(settings.with_overrides(database_url="sqlite://"))
    rt.init_db()
    assert rt.coordination.leading and rt.coordination.listening
    assert not rt.coordination.shared
    with rt.db.session() as s:
        [this] = rt.coordination.replicas(s)
    assert this["name"] == rt.coordination.name and this["this"] and this["leader"]
    rt.db.dispose()


def test_jobs_run_one_at_a_time(rt: Runtime) -> None:
    jobs = rt.coordination
    inside, release = threading.Event(), threading.Event()

    def hold() -> None:
        with jobs.job("rules"):
            inside.set()
            release.wait(5)

    holder = threading.Thread(target=hold)
    holder.start()
    assert inside.wait(5)
    with pytest.raises(JobBusy, match="rules is running"), jobs.job("rules", wait=0.1):
        pass
    with jobs.job("retention", wait=0.1):  # another job isn't held up
        pass
    release.set()
    holder.join(5)
    with jobs.job("rules", wait=1), jobs.job("rules"):  # and a thread may go back in
        pass


def test_a_busy_job_is_a_409(client, monkeypatch) -> None:
    rt = client.app.state.rt
    inside, release = threading.Event(), threading.Event()

    def hold() -> None:
        with rt.coordination.job("retention"):
            inside.set()
            release.wait(10)

    holder = threading.Thread(target=hold)
    holder.start()
    assert inside.wait(5)
    # The request waits its turn (JOB_WAIT_SECONDS), then gives up.
    monkeypatch.setattr(evidence_routes, "JOB_WAIT_SECONDS", 0.2)
    try:
        resp = client.post("/v1/ledger/retention/run", headers=ADMIN)
    finally:
        release.set()
        holder.join(5)
    assert resp.status_code == 409 and "retention is running" in resp.json()["detail"]
    assert client.post("/v1/ledger/retention/run", headers=ADMIN).status_code == 200


def test_lock_keys_differ() -> None:
    names = ["leader", "startup", "posture-scan", "rules", "retention", "microsoft-sync",
             "issues", "developer-mcp", "instruction-checks", "instruction-classifier",
             "identity"]  # fmt: skip
    assert len({lock_key(n) for n in names}) == len(names)
    assert all(-(2**31) <= lock_key(n) < 2**31 for n in names)


# ---------------------------------------------------------------------- PostgreSQL


@pytest.fixture
def pair(settings: Settings) -> Iterator[tuple[Runtime, Runtime]]:
    """Two replicas on one database, started as the control plane starts them (without
    their scheduled work)."""
    quiet = settings.with_overrides(
        delivery_interval_seconds=0, issues_interval_seconds=0, posture_interval_seconds=0
    )
    replicas = [Runtime(quiet), Runtime(quiet)]
    for replica in replicas:
        replica.init_db()
        replica.coordination.retry_seconds = 0.2
        replica.coordination.start()
    yield replicas[0], replicas[1]
    for replica in replicas:
        replica.coordination.stop()
        replica.db.dispose()


@postgres
def test_one_replica_leads_and_another_takes_over(pair: tuple[Runtime, Runtime]) -> None:
    a, b = pair
    until(lambda: a.coordination.leading or b.coordination.leading)
    time.sleep(0.5)  # and the other doesn't, however often it tries
    assert a.coordination.leading != b.coordination.leading
    leader, other = (a, b) if a.coordination.leading else (b, a)
    with other.db.session() as s:
        seen = other.coordination.replicas(s)
    assert {r["name"] for r in seen} == {a.coordination.name, b.coordination.name}
    assert [r["name"] for r in seen if r["leader"]] == [leader.coordination.name]
    assert [r["this"] for r in seen if r["name"] == other.coordination.name] == [True]

    leader.coordination.stop()  # it stops, or loses the database
    assert not leader.coordination.leading
    until(lambda: other.coordination.leading, timeout=5)


@postgres
def test_another_agentgov_on_the_server_is_apart(pair: tuple[Runtime, Runtime]) -> None:
    """Another AgentGov on the same PostgreSQL server, on a database of its own, leads its
    own replicas, and neither lists the other's."""
    a, b = pair
    neighbour = Coordinator(Database(POSTGRES), retry_seconds=0.2)
    neighbour.start()
    try:
        until(lambda: neighbour.leading)
        until(lambda: a.coordination.leading or b.coordination.leading)
        with a.db.session() as s:
            seen = {r["name"] for r in a.coordination.replicas(s)}
        assert seen == {a.coordination.name, b.coordination.name}
    finally:
        neighbour.stop()
        neighbour.db.dispose()


@postgres
def test_every_connection_keeps_alive(settings: Settings) -> None:
    """The server lets go of a vanished replica's locks, a job's as well as the leader's,
    within half a minute, not when the operating system's two hours are up."""
    db = Database(settings.database_url)
    try:
        for _ in range(2):  # a new connection, then the same one back from the pool
            with db.engine.connect() as connection:
                server = connection.exec_driver_sql("SHOW tcp_keepalives_idle").scalar()
                client = connection.connection.dbapi_connection.info.get_parameters()
                assert server == "10" and client["keepalives_idle"] == "10"
    finally:
        db.dispose()


@postgres
def test_a_replica_out_of_touch_lists_itself(settings: Settings) -> None:
    rt = Runtime(settings)
    rt.init_db()  # and its coordination not started: as when it lost the database
    with rt.db.session() as s:
        assert rt.coordination.replicas(s) == [
            {
                "name": rt.coordination.name,
                "leader": False,
                "listening": False,
                "database": "postgresql",
                "this": True,
                "connected_since": None,
            }
        ]
    rt.db.dispose()


@postgres
def test_changes_reach_every_replica(pair: tuple[Runtime, Runtime]) -> None:
    a, b = pair
    until(lambda: a.coordination.listening and b.coordination.listening)
    heard: list[set[str] | None] = []
    b.coordination.on_remote = heard.append
    with a.db.session() as s:
        mark_changed(s, "agents", "ledger")
    until(lambda: heard)
    assert heard == [{"agents"}]  # the ledger only to the replica that wrote it
    with a.db.session() as s:
        mark_changed(s, "ledger")
    with a.db.session() as s:
        mark_changed(s, "features")
    until(lambda: len(heard) == 2)
    assert heard[1] == {"features"}
    # Rolled back: nobody hears of it.
    with pytest.raises(RuntimeError), a.db.session() as s:
        mark_changed(s, "toolservers")
        raise RuntimeError("no")
    # A replica doesn't hear its own changes again.
    mine: list[Any] = []
    a.coordination.on_remote = mine.append
    with a.db.session() as s:
        mark_changed(s, "blueprints")
    until(lambda: len(heard) == 3)
    assert heard[2] == {"blueprints"} and mine == []


@postgres
def test_blocking_reaches_opa_through_any_replica(pair: tuple[Runtime, Runtime]) -> None:
    a, b = pair
    until(lambda: a.coordination.listening and b.coordination.listening)
    with a.db.session() as s:
        agent = agents.register(
            s,
            a.settings,
            {"name": "support-bot", "owner": "cx", "sponsors": ["alice@example.com"]},
            actor="admin:test",
            approve=True,
        )
        agent_id = agent.id

    async def long_poll() -> float:
        b.bundles.bind_loop(asyncio.get_running_loop())
        before = await asyncio.to_thread(b.bundles.current)
        waiting = asyncio.ensure_future(b.bundles.wait_for_change(before.etag, 20))
        await asyncio.sleep(0.3)  # OPA is waiting on replica b
        started = time.monotonic()
        # An administrator blocks the agent on replica a.
        await asyncio.to_thread(block, a, agent_id)
        changed = await waiting
        assert changed is not None and changed.etag != before.etag
        return time.monotonic() - started

    took = asyncio.run(long_poll())
    assert took < 1.0, took


def block(rt: Runtime, agent_id: str) -> None:
    with rt.db.session() as s:
        agents.transition(s, rt.settings, agents.get(s, agent_id), "block", actor="admin:test")


@postgres
def test_a_job_runs_on_one_replica_at_a_time(pair: tuple[Runtime, Runtime]) -> None:
    a, b = pair
    inside, release = threading.Event(), threading.Event()

    def hold() -> None:
        with a.coordination.job("retention"):
            inside.set()
            release.wait(10)

    holder = threading.Thread(target=hold)
    holder.start()
    assert inside.wait(5)
    with (
        pytest.raises(JobBusy, match="on this replica or another"),
        b.coordination.job("retention", wait=0.3),
    ):
        pass
    release.set()
    holder.join(5)
    with b.coordination.job("retention", wait=2):
        pass


@postgres
def test_a_job_that_lost_its_lock_stops(pair: tuple[Runtime, Runtime]) -> None:
    """The database drops the connection that holds a running job's lock (as when it
    restarts): another replica may run the job now, and this run writes nothing more."""
    a, b = pair
    with a.coordination.job("retention"):
        with a.db.session() as s:
            ledger.append(s, type="test.before", actor="test")
        with b.db.session() as s:
            s.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' "
                    "AND classid = :space AND objid = :key AND objsubid = 2"
                ),
                {"space": LOCK_SPACE, "key": lock_key("retention") & 0xFFFFFFFF},
            )
        # The other replica runs it.
        with b.coordination.job("retention", wait=5), b.db.session() as s:
            ledger.append(s, type="test.elsewhere", actor="test")
        with pytest.raises(JobLost, match="retention lost its lock"), a.db.session() as s:
            ledger.append(s, type="test.after", actor="test")
    with a.db.session() as s:
        types = set(s.scalars(select(LedgerEntry.type).where(LedgerEntry.type.like("test.%"))))
    assert types == {"test.before", "test.elsewhere"}
    # The next run takes the lock again, and writes as usual.
    with a.coordination.job("retention", wait=5), a.db.session() as s:
        ledger.append(s, type="test.again", actor="test")


@postgres
def test_a_replica_that_lost_the_database_hears_everything(
    pair: tuple[Runtime, Runtime],
) -> None:
    _, b = pair
    until(lambda: b.coordination.listening)
    heard: list[Any] = []
    b.coordination.on_remote = heard.append
    with b.db.session() as s:
        # The database drops replica b's coordination connection.
        s.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE application_name = :name"
            ),
            {"name": f"agentgov/{b.coordination.name}"},
        )
    until(lambda: None in heard, timeout=10)
    until(lambda: b.coordination.listening)


def test_the_database_tells_replicas_with_the_commit() -> None:
    """Without PostgreSQL there is no one to tell: a commit names its topics locally."""
    db = Database("sqlite://")
    told: list[Any] = []
    db.before_commit = lambda tx, topics: told.append(topics)
    with db.session() as s:
        mark_changed(s, "agents")
    with db.session():
        pass
    assert told == [{"agents"}]
    db.dispose()


def test_a_coordinator_alone() -> None:
    db = Database("sqlite://")
    alone = Coordinator(db)
    alone.start()  # nothing to start on SQLite
    assert alone.status()["leader"] is True
    alone.received('{"from": "other", "topics": ["agents"]}')
    alone.received("not json")  # ignored, with a warning
    alone.stop()
    db.dispose()
