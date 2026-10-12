"""Tamper-evident evidence ledger.

Every governance-relevant event (lifecycle changes, admin actions, policy
decisions, approvals, OPA decision logs) is appended to a hash chain. Each
entry's hash covers the previous entry's hash, so editing or deleting any
stored entry is detectable by :func:`verify`.

Checkpoints keep points of the chain for good (docs/evidence.md). Once the entries
up to a checkpoint are archived and removed (agentgov.retention), the chain in the
database goes on from it, and :func:`verify_records` checks the archives offline.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from sqlalchemy import event, select, update
from sqlalchemy.orm import Session, SessionTransaction

from agentgov import db, ids
from agentgov.db import mark_changed
from agentgov.models import Agent, LedgerCheckpoint, LedgerEntry, LedgerHead

GENESIS = "0" * 64
# A transaction's entries, until it commits; and how many there were when each of its
# savepoints began.
_PENDING = "agentgov.ledger.pending"
_SAVEPOINTS = "agentgov.ledger.savepoints"


def ensure_head(session: Session) -> None:
    if session.get(LedgerHead, 1) is None:
        session.add(LedgerHead(id=1, last_seq=0, last_hash=GENESIS))
        session.flush()


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _payload(entry: LedgerEntry) -> dict[str, Any]:
    payload = {
        "seq": entry.seq,
        "id": entry.id,
        "ts": ids.isoformat(entry.ts),
        "type": entry.type,
        "severity": entry.severity,
        "actor": entry.actor,
        "agent_id": entry.agent_id,
        "agent_name": entry.agent_name,
        "action": entry.action,
        "resource": entry.resource,
        "decision": entry.decision,
        "reason": entry.reason,
        "details": entry.details or {},
        "trace_id": entry.trace_id,
    }
    # Added later: hashed only when set, so earlier entries keep their hashes.
    if entry.on_behalf_of is not None:
        payload["on_behalf_of"] = entry.on_behalf_of
    return payload


def compute_hash(prev_hash: str, entry: LedgerEntry) -> str:
    return hashlib.sha256(prev_hash.encode() + _canonical(_payload(entry))).hexdigest()


def record_hash(prev_hash: str, record: dict[str, Any]) -> str:
    """The hash of an entry as :func:`to_dict` writes it (an export's or an archive's line)."""
    payload = {k: v for k, v in record.items() if k not in ("prev_hash", "hash")}
    if payload.get("on_behalf_of") is None:
        payload.pop("on_behalf_of", None)
    return hashlib.sha256(prev_hash.encode() + _canonical(payload)).hexdigest()


def append(
    session: Session,
    *,
    type: str,
    actor: str,
    severity: str = "info",
    agent: Agent | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    decision: str | None = None,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
    trace_id: str | None = None,
    on_behalf_of: str | None = None,
    ts: datetime | None = None,
) -> LedgerEntry:
    """Append an entry with the caller's transaction.

    The entry is written as the transaction commits, after everything else it changed:
    appenders lock the chain's head to extend it one at a time, and the head is then the
    last row a transaction locks, so two transactions that lock the same rows can't
    deadlock over it. An entry rolled back with its transaction, or with a savepoint it was
    appended in, isn't written. Until the commit it has no seq or hash, and the
    transaction's own queries don't see it.
    """
    entry = LedgerEntry(
        id=ids.new_id(ids.EVENT),
        ts=ts,
        type=type,
        severity=severity,
        actor=actor,
        agent_id=agent.id if agent else agent_id,
        agent_name=agent.name if agent else agent_name,
        action=action,
        resource=resource,
        decision=decision,
        reason=reason,
        details=details or {},
        trace_id=trace_id,
        on_behalf_of=on_behalf_of,
    )
    session.info.setdefault(_PENDING, []).append(entry)
    # For what sends the ledger on (agentgov.secops.delivery), once this commits.
    mark_changed(session, "ledger")
    return entry


def _write_pending(session: Session) -> None:
    """Write the transaction's entries, in the order they were appended. Updating the head
    row first takes a write lock held until the commit: appenders take turns."""
    pending: list[LedgerEntry] | None = session.info.pop(_PENDING, None)
    if not pending:
        return
    ensure_head(session)
    session.execute(
        update(LedgerHead).where(LedgerHead.id == 1).values(last_seq=LedgerHead.last_seq)
    )
    head = session.get(LedgerHead, 1, populate_existing=True)
    assert head is not None
    for entry in pending:
        entry.seq = head.last_seq + 1
        # When it was written, unless the caller said when it happened: in the chain's order.
        entry.ts = entry.ts or ids.utcnow()
        entry.prev_hash = head.last_hash
        entry.hash = compute_hash(head.last_hash, entry)
        head.last_seq, head.last_hash = entry.seq, entry.hash
        session.add(entry)
    session.flush()


db.WRITE_LAST.append(_write_pending)


@event.listens_for(Session, "after_transaction_create")
def _savepoint_begins(session: Session, transaction: SessionTransaction) -> None:
    if transaction.nested:
        marks = session.info.setdefault(_SAVEPOINTS, {})
        marks[transaction] = len(session.info.get(_PENDING) or ())


@event.listens_for(Session, "after_soft_rollback")
def _rolled_back(session: Session, previous: SessionTransaction) -> None:
    """Entries appended since a savepoint that rolled back, or in a transaction that did,
    go with them."""
    if previous.nested:
        start = (session.info.get(_SAVEPOINTS) or {}).get(previous)
        pending = session.info.get(_PENDING)
        if start is not None and pending is not None:
            del pending[start:]
    elif previous.parent is None:
        session.info.pop(_PENDING, None)


@event.listens_for(Session, "after_transaction_end")
def _transaction_ends(session: Session, transaction: SessionTransaction) -> None:
    if transaction.parent is None:
        session.info.pop(_SAVEPOINTS, None)


def iter_entries(
    session: Session, *, batch: int = 1000, after: int = 0, until: int | None = None
) -> Iterator[LedgerEntry]:
    last = after
    while True:
        stmt = select(LedgerEntry).where(LedgerEntry.seq > last)
        if until is not None:
            stmt = stmt.where(LedgerEntry.seq <= until)
        rows = session.scalars(stmt.order_by(LedgerEntry.seq).limit(batch)).all()
        if not rows:
            return
        yield from rows
        last = rows[-1].seq


def base(session: Session) -> tuple[int, str]:
    """Where the chain in the database starts: the checkpoint the entries before it were
    archived up to, or the beginning."""
    checkpoint = session.scalar(
        select(LedgerCheckpoint)
        .where(LedgerCheckpoint.pruned_at.is_not(None))
        .order_by(LedgerCheckpoint.seq.desc())
        .limit(1)
    )
    return (checkpoint.seq, checkpoint.hash) if checkpoint is not None else (0, GENESIS)


def verify(session: Session, *, start: tuple[int, str] | None = None) -> dict[str, Any]:
    """Recompute the chain and report the first inconsistency, if any.

    ``start`` is the ``(seq, hash)`` of an entry that was already verified: only the
    entries after it are checked. Only a full verification detects later edits to
    entries before ``start``. A full verification starts where the chain in the
    database does: after the entries archived (``from``).
    """
    # The head is read first and the chain checked up to it: entries committed while
    # we read are beyond it, so concurrent appends cannot look like a broken chain.
    head = session.get(LedgerHead, 1, populate_existing=True)
    floor = base(session)
    checked, prev = start if start is not None and start[0] >= floor[0] else floor
    expected_seq = checked + 1
    until = head.last_seq if head is not None else None
    for entry in iter_entries(session, after=checked, until=until):
        problem = None
        if entry.seq != expected_seq:
            problem = f"missing entry before seq {entry.seq}"
        elif entry.prev_hash != prev:
            problem = "prev_hash does not match the previous entry"
        elif compute_hash(prev, entry) != entry.hash:
            problem = "entry contents do not match its hash"
        if problem:
            return {"valid": False, "checked": checked, "broken_at": entry.seq, "problem": problem}
        prev = entry.hash
        expected_seq += 1
        checked += 1
    if head is None and checked:
        return {
            "valid": False,
            "checked": checked,
            "broken_at": None,
            "problem": "chain head is missing",
        }
    if head is not None and (head.last_seq != checked or head.last_hash != prev):
        return {
            "valid": False,
            "checked": checked,
            "broken_at": checked + 1,
            "problem": "chain head does not match the last entry (entries removed?)",
        }
    return {"valid": True, "checked": checked, "broken_at": None, "head": prev, "from": floor[0]}


def verify_records(records: Any, *, start: tuple[int, str] | None = None) -> dict[str, Any]:
    """Check a run of entries as :func:`to_dict` writes them (an export, or archives in
    order), without the database: each links to the one before and matches its hash.
    ``start`` is the ``(seq, hash)`` the first must follow; by default, whatever its own
    ``prev_hash`` says (a checkpoint or another archive vouches for that)."""
    count, first, last = 0, None, None
    expected: tuple[int, str] | None = start
    for record in records:
        seq, prev = record.get("seq"), record.get("prev_hash")
        if expected is None:
            expected = (seq - 1, prev)
        problem = None
        if seq != expected[0] + 1:
            problem = f"missing entry before seq {seq}"
        elif prev != expected[1]:
            problem = "prev_hash does not match the previous entry"
        elif record_hash(prev, record) != record.get("hash"):
            problem = "entry contents do not match its hash"
        if problem:
            return {"valid": False, "checked": count, "broken_at": seq, "problem": problem}
        first = seq if first is None else first
        expected, last = (seq, record["hash"]), record
        count += 1
    return {
        "valid": True,
        "checked": count,
        "first": first,
        "follows": start[1] if start else None,
        "last": last["seq"] if last else None,
        "head": last["hash"] if last else None,
    }


def statement(seq: int, hash_: str) -> bytes:
    """What a time-stamping authority signs for a checkpoint: the head it vouches for."""
    return f"agentgov ledger checkpoint seq={seq} hash={hash_}\n".encode()


def checkpoint(session: Session) -> LedgerCheckpoint | None:
    """Keep the chain's current head as a checkpoint (the one there already is, if the
    chain hasn't grown since). None while the ledger is empty."""
    head = session.get(LedgerHead, 1, populate_existing=True)
    if head is None or head.last_seq == 0:
        return None
    existing = session.get(LedgerCheckpoint, head.last_seq)
    if existing is not None:
        return existing
    entry = session.get(LedgerEntry, head.last_seq)
    point = LedgerCheckpoint(
        seq=head.last_seq,
        hash=head.last_hash,
        entry_ts=entry.ts if entry is not None else ids.utcnow(),
    )
    session.add(point)
    session.flush()
    return point


def checkpoint_dict(point: LedgerCheckpoint) -> dict[str, Any]:
    return {
        "seq": point.seq,
        "hash": point.hash,
        "entry_ts": ids.isoformat(point.entry_ts),
        "created_at": ids.isoformat(point.created_at),
        "statement": statement(point.seq, point.hash).decode(),
        "tsa_url": point.tsa_url,
        "timestamped": point.timestamp is not None,
        "timestamped_at": ids.isoformat(point.timestamped_at),
        "timestamp_error": point.timestamp_error,
        # Its entry in the transparency log, if it has one.
        "log": {
            "url": point.tlog_url,
            "logged": point.tlog_entry is not None,
            "index": point.tlog_index,
            "logged_at": ids.isoformat(point.tlog_logged_at),
            "checked": point.tlog_checked,
            "error": point.tlog_error,
        },
        "archive": point.archive,
        "archive_sha256": point.archive_sha256,
        "archived_from": point.archived_from,
        "pruned_at": ids.isoformat(point.pruned_at),
    }


class IntegrityMonitor:
    """Ledger integrity for dashboards, without re-hashing the whole chain on every request.

    New entries are verified incrementally; the whole chain is re-verified when the last
    full check is older than ``full_every`` seconds, or after a failed check.
    """

    def __init__(self, full_every: float = 300.0) -> None:
        self.full_every = full_every
        self._lock = threading.Lock()
        self._last: dict[str, Any] | None = None
        self._full_at = 0.0

    def check(self, session: Session) -> dict[str, Any]:
        with self._lock:
            last, now = self._last, time.monotonic()
            if last is None or not last["valid"] or now - self._full_at >= self.full_every:
                result = verify(session)
                self._full_at = now
            else:
                result = verify(session, start=(last["checked"], last["head"]))
            self._last = result
            return dict(result)


def with_trace_link(entry: dict[str, Any], trace_url: str | None) -> dict[str, Any]:
    """Add ``trace_url`` to an entry recorded with a trace ID, when a viewer is configured."""
    if trace_url and entry.get("trace_id"):
        entry["trace_url"] = trace_url.replace("{trace_id}", entry["trace_id"])
    return entry


def to_dict(entry: LedgerEntry) -> dict[str, Any]:
    data = _payload(entry)
    data["prev_hash"] = entry.prev_hash
    data["hash"] = entry.hash
    return data
