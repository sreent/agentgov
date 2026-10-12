"""Several control-plane replicas on one PostgreSQL database.

Replicas keep nothing to themselves that another one needs: what they share is in the
database, and they coordinate through it.

* **Changes.** A transaction that changes what OPA, the gateway or a worker acts on names
  topics (``db.mark_changed``). On PostgreSQL the topics go out with the commit
  (``NOTIFY``, which PostgreSQL delivers only if the transaction commits), and every
  replica acts on them as on its own: OPA instances long-polling any replica get the new
  bundle at once, and the workers that care wake. A replica that lost the database and
  found it again acts as if everything changed.
* **Scheduled work** runs on one replica at a time, the leader: the one that holds a
  session-level advisory lock. When the leader stops, or its connection to the database
  goes, the lock goes with it and another replica takes over within seconds.
* **Jobs** that an administrator can start as well (a posture scan, the management rules,
  retention, the Microsoft sync) run on one replica at a time, under an advisory lock of
  their own. A request that finds its job running waits a little, then gets a 409.

On SQLite (development: one process) the same calls stay in the process: it leads, and
its jobs take locks of its own.

The control plane's connections need PostgreSQL's session features (``LISTEN``, advisory
locks): connect it directly, or through a pooler in session mode.
"""

from __future__ import annotations

import contextlib
import json
import logging
import secrets
import socket
import threading
import time
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from agentgov.db import CLIENT_KEEPALIVES, SERVER_KEEPALIVES, Database
from agentgov.registry.errors import Conflict

log = logging.getLogger(__name__)

CHANNEL = "agentgov_changes"
# Topics only the replica that wrote them acts on. Every ledger entry would otherwise reach
# every replica, and each replica's delivery worker sends what it writes already.
LOCAL_TOPICS = frozenset({"ledger"})
# NOTIFY carries up to 8000 bytes; past this, the other replicas hear that everything
# changed.
MAX_PAYLOAD = 7000
EVERYTHING = "*"
# Advisory locks in a key space of their own (two 32-bit keys), apart from the migrations'
# single-key lock.
LOCK_SPACE = 0x41474A42  # "AGJB"
LEADER = "leader"
# How often a replica that doesn't lead tries to.
LEADER_RETRY_SECONDS = 5.0
# How long a job that finds another run of it going waits by default, when asked to wait.
JOB_POLL_SECONDS = 0.5
APPLICATION = "agentgov"


class JobBusy(Conflict):
    """The job is running already, on this replica or another."""


def lock_key(name: str) -> int:
    """The second key of a job's advisory lock (a signed 32-bit integer)."""
    value = zlib.crc32(f"agentgov:{name}".encode())
    return value - (1 << 32) if value >= (1 << 31) else value


def replica_name() -> str:
    """This process's name among the replicas: its host (in Kubernetes, the pod's name) and
    a random suffix, so that a restarted process isn't taken for the one before it."""
    return f"{socket.gethostname()[:40]}-{secrets.token_hex(3)}"


class Coordinator:
    """This replica's part in the change feed, the leadership and the jobs."""

    def __init__(
        self,
        db: Database,
        *,
        on_remote: Callable[[set[str] | None], None] | None = None,
        on_leader: Callable[[bool], None] | None = None,
        retry_seconds: float = LEADER_RETRY_SECONDS,
    ) -> None:
        self.db = db
        self.name = replica_name()
        # Several replicas need PostgreSQL; on SQLite this process is the only one.
        self.shared = db.engine.dialect.name == "postgresql"
        self.on_remote = on_remote or (lambda topics: None)
        self.on_leader = on_leader or (lambda leading: None)
        self.retry_seconds = retry_seconds
        self._leading = not self.shared
        self._listening = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._held = threading.local()
        if self.shared:
            db.before_commit = self.publish

    # -- state -------------------------------------------------------------------------
    @property
    def leading(self) -> bool:
        """Whether this replica runs the scheduled work."""
        return self._leading

    @property
    def listening(self) -> bool:
        """Whether this replica hears the others' changes (always, alone on SQLite)."""
        return self._listening or not self.shared

    def status(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "leader": self.leading,
            "listening": self.listening,
            "database": "postgresql" if self.shared else "sqlite",
        }

    # -- lifecycle ---------------------------------------------------------------------
    def start(self) -> None:
        if not self.shared or self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="coordination", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # -- changes -----------------------------------------------------------------------
    def publish(self, session: Session, topics: set[str]) -> None:
        """Tell the other replicas about this transaction's changes, with its commit."""
        shared = sorted(topics - LOCAL_TOPICS)
        if not shared:
            return
        payload = json.dumps({"from": self.name, "topics": shared}, separators=(",", ":"))
        if len(payload.encode()) > MAX_PAYLOAD:
            payload = json.dumps({"from": self.name, "topics": [EVERYTHING]})
        session.execute(
            text("SELECT pg_notify(:channel, :payload)"),
            {"channel": CHANNEL, "payload": payload},
        )

    def received(self, payload: str) -> None:
        """Act on another replica's change notice."""
        try:
            note = json.loads(payload)
            sender, topics = str(note["from"]), {str(t) for t in note["topics"]}
        except (ValueError, KeyError, TypeError):
            log.warning("ignoring a malformed change notice: %.200s", payload)
            return
        if sender == self.name:
            return  # acted on when it committed
        self._remote(None if EVERYTHING in topics else topics)

    def _remote(self, topics: set[str] | None) -> None:
        try:
            self.on_remote(topics)
        except Exception:
            log.exception("acting on another replica's change failed")

    # -- the coordination connection ---------------------------------------------------
    def _connect(self) -> Any:
        """A connection of its own (outside the pool), in autocommit, with keepalives."""
        engine = self.db.engine
        cargs, cparams = engine.dialect.create_connect_args(engine.url)
        for key, value in CLIENT_KEEPALIVES.items():
            cparams.setdefault(key, value)
        cparams["application_name"] = f"{APPLICATION}/{self.name}"[:63]
        cparams["autocommit"] = True
        connection = engine.dialect.connect(*cargs, **cparams)
        for statement in SERVER_KEEPALIVES:
            connection.execute(statement)
        return connection

    def _run(self) -> None:
        backoff, first = 1.0, True
        while not self._stop.is_set():
            connection = None
            try:
                connection = self._connect()
                connection.execute(f"LISTEN {CHANNEL}")
                self._listening = True
                if not first:
                    # Whatever changed while this replica wasn't listening went unheard.
                    self._remote(None)
                first, backoff = False, 1.0
                self._serve(connection)
            except Exception as exc:  # the database restarting, a network blip
                if not self._stop.is_set():
                    log.warning("lost touch with the other replicas: %s", exc)
            finally:
                self._listening = False
                self._lead(False)  # the lock went with the connection
                if connection is not None:
                    with contextlib.suppress(Exception):
                        connection.close()
            self._stop.wait(backoff)
            backoff = min(backoff * 2, 30.0)

    def _serve(self, connection: Any) -> None:
        """Listen for changes, and try to lead now and then while another replica does."""
        next_try = 0.0
        while not self._stop.is_set():
            if not self._leading and time.monotonic() >= next_try:
                row = connection.execute(
                    "SELECT pg_try_advisory_lock(%s, %s)", (LOCK_SPACE, lock_key(LEADER))
                ).fetchone()
                if row and row[0]:
                    self._lead(True)
                next_try = time.monotonic() + self.retry_seconds
            for notice in connection.notifies(timeout=1.0):
                self.received(notice.payload)

    def _lead(self, leading: bool) -> None:
        if leading == self._leading:
            return
        self._leading = leading
        log.info("replica %s %s the leader", self.name, "is now" if leading else "is no longer")
        try:
            self.on_leader(leading)
        except Exception:
            log.exception("acting on a change of leader failed")

    # -- jobs --------------------------------------------------------------------------
    def _local(self, name: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(name, threading.Lock())

    def _holding(self) -> set[str]:
        held: set[str] | None = getattr(self._held, "names", None)
        if held is None:
            held = self._held.names = set()
        return held

    @contextmanager
    def job(self, name: str, *, wait: float | None = None) -> Iterator[None]:
        """Run ``name`` on one replica at a time (and in one thread of each). ``wait``: how
        long to wait for a run already going (None: as long as it takes); past that,
        JobBusy. A thread that holds the job already goes straight in."""
        holding = self._holding()
        if name in holding:
            yield
            return
        deadline = None if wait is None else time.monotonic() + wait
        local = self._local(name)
        if not local.acquire(timeout=-1 if wait is None else wait):
            raise self._busy(name)
        try:
            with self._advisory(name, deadline):
                holding.add(name)
                try:
                    yield
                finally:
                    holding.discard(name)
        finally:
            local.release()

    def _busy(self, name: str) -> JobBusy:
        where = "on this replica or another" if self.shared else "already"
        return JobBusy(f"{name} is running {where}; try again in a moment")

    @contextmanager
    def _advisory(self, name: str, deadline: float | None) -> Iterator[None]:
        if not self.shared:
            yield
            return
        params = {"space": LOCK_SPACE, "key": lock_key(name)}
        connection = self.db.engine.connect()
        try:
            while True:
                got = connection.execute(
                    text("SELECT pg_try_advisory_lock(:space, :key)"), params
                ).scalar()
                connection.commit()
                if got:
                    break
                if self._stop.is_set() or (deadline is not None and time.monotonic() >= deadline):
                    raise self._busy(name)
                time.sleep(JOB_POLL_SECONDS)
            try:
                yield
            finally:
                try:
                    connection.execute(text("SELECT pg_advisory_unlock(:space, :key)"), params)
                    connection.commit()
                except Exception:
                    # Closing the connection lets the lock go, rather than keeping it in
                    # the pool.
                    connection.invalidate()
        finally:
            connection.close()

    # -- the replicas ------------------------------------------------------------------
    def replicas(self, session: Session) -> list[dict[str, Any]]:
        """The replicas connected to the database now, and which one leads. This one is
        among them even while it has lost touch with the others (``listening`` false)."""
        if not self.shared:
            return [{**self.status(), "this": True, "connected_since": None}]
        # Of this database only: another AgentGov on the same server has replicas, and a
        # leader, of its own.
        rows = session.execute(
            text(
                "SELECT a.application_name, a.backend_start, EXISTS ("
                "  SELECT 1 FROM pg_locks l WHERE l.pid = a.pid AND l.locktype = 'advisory'"
                "  AND l.granted AND l.classid = :space AND l.objid = :key AND l.objsubid = 2"
                ") FROM pg_stat_activity a WHERE a.datname = current_database() "
                "AND a.application_name LIKE :prefix ORDER BY a.backend_start"
            ),
            {
                "space": LOCK_SPACE,
                "key": lock_key(LEADER) & 0xFFFFFFFF,
                "prefix": f"{APPLICATION}/%",
            },
        ).all()
        found = []
        for application, since, leads in rows:
            name = application.removeprefix(f"{APPLICATION}/")
            found.append(
                {
                    "name": name,
                    "leader": bool(leads),
                    "listening": True,
                    "database": "postgresql",
                    "this": name == self.name,
                    "connected_since": since.isoformat() if since else None,
                }
            )
        if not any(r["this"] for r in found):
            found.append({**self.status(), "this": True, "connected_since": None})
        return found
