"""Tamper-evident evidence ledger.

Every governance-relevant event (lifecycle changes, admin actions, policy
decisions, approvals, OPA decision logs) is appended to a hash chain. Each
entry's hash covers the previous entry's hash, so editing or deleting any
stored entry is detectable by :func:`verify`.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from agentgov import ids
from agentgov.models import Agent, LedgerEntry, LedgerHead

GENESIS = "0" * 64


def ensure_head(session: Session) -> None:
    if session.get(LedgerHead, 1) is None:
        session.add(LedgerHead(id=1, last_seq=0, last_hash=GENESIS))
        session.flush()


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _payload(entry: LedgerEntry) -> dict[str, Any]:
    return {
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


def compute_hash(prev_hash: str, entry: LedgerEntry) -> str:
    return hashlib.sha256(prev_hash.encode() + _canonical(_payload(entry))).hexdigest()


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
    ts: datetime | None = None,
) -> LedgerEntry:
    """Append an entry inside the caller's transaction.

    Updating the head row first takes a write lock that is held until the
    caller commits, so concurrent appenders extend the chain one at a time.
    """
    ensure_head(session)
    session.execute(
        update(LedgerHead).where(LedgerHead.id == 1).values(last_seq=LedgerHead.last_seq)
    )
    head = session.get(LedgerHead, 1, populate_existing=True)
    assert head is not None
    entry = LedgerEntry(
        seq=head.last_seq + 1,
        id=ids.new_id(ids.EVENT),
        ts=ts or ids.utcnow(),
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
        prev_hash=head.last_hash,
    )
    entry.hash = compute_hash(head.last_hash, entry)
    head.last_seq = entry.seq
    head.last_hash = entry.hash
    session.add(entry)
    session.flush()
    return entry


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


def verify(session: Session, *, start: tuple[int, str] | None = None) -> dict[str, Any]:
    """Recompute the chain and report the first inconsistency, if any.

    ``start`` is the ``(seq, hash)`` of an entry that was already verified: only the
    entries after it are checked. Only a full verification detects later edits to
    entries before ``start``.
    """
    # The head is read first and the chain checked up to it: entries committed while
    # we read are beyond it, so concurrent appends cannot look like a broken chain.
    head = session.get(LedgerHead, 1, populate_existing=True)
    checked, prev = start or (0, GENESIS)
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
    return {"valid": True, "checked": checked, "broken_at": None, "head": prev}


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
