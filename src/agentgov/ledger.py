"""Tamper-evident evidence ledger.

Every governance-relevant event (lifecycle changes, admin actions, policy
decisions, approvals, OPA decision logs) is appended to a hash chain. Each
entry's hash covers the previous entry's hash, so editing or deleting any
stored entry is detectable by :func:`verify`.
"""

from __future__ import annotations

import hashlib
import json
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


def iter_entries(session: Session, *, batch: int = 1000) -> Iterator[LedgerEntry]:
    last = 0
    while True:
        rows = session.scalars(
            select(LedgerEntry).where(LedgerEntry.seq > last).order_by(LedgerEntry.seq).limit(batch)
        ).all()
        if not rows:
            return
        yield from rows
        last = rows[-1].seq


def verify(session: Session) -> dict[str, Any]:
    """Recompute the chain and report the first inconsistency, if any."""
    prev = GENESIS
    expected_seq = 1
    checked = 0
    for entry in iter_entries(session):
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
    head = session.get(LedgerHead, 1)
    if head is not None and (head.last_seq != checked or head.last_hash != prev):
        return {
            "valid": False,
            "checked": checked,
            "broken_at": checked + 1,
            "problem": "chain head does not match the last entry (entries removed?)",
        }
    return {"valid": True, "checked": checked, "broken_at": None, "head": prev}


def to_dict(entry: LedgerEntry) -> dict[str, Any]:
    data = _payload(entry)
    data["prev_hash"] = entry.prev_hash
    data["hash"] = entry.hash
    return data
