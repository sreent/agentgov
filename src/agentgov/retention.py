"""How long AgentGov keeps what it records (docs/evidence.md).

The ledger is evidence: nothing leaves it unarchived. Every
``AGENTGOV_LEDGER_CHECKPOINT_HOURS`` its head is kept as a checkpoint, which a
time-stamping authority signs when ``AGENTGOV_LEDGER_TSA_URL`` is set
(agentgov.timestamping). With ``AGENTGOV_LEDGER_RETENTION_DAYS``, entries older than
that are written to an archive in ``AGENTGOV_LEDGER_ARCHIVE_DIR`` (gzipped JSON Lines,
checked link by link as they are written), a checkpoint records the archive and its
SHA-256, and only then do the entries leave the database: the chain there goes on from
that checkpoint, and the archive verifies offline (``agentgov ledger verify --file``).
Entries an active destination hasn't been sent yet stay, while security operations are on.

The operational records whose history is in the ledger (daily activity and model usage,
risk signals, notifications sent, decided approval requests, resolved findings, ended
access assignments, developers' MCP servers not reported since) go after
``AGENTGOV_DATA_RETENTION_DAYS``.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.models import (
    AccessAssignment,
    AgentActivity,
    ApprovalRequest,
    Destination,
    Finding,
    LedgerCheckpoint,
    LedgerEntry,
    LedgerHead,
    McpSighting,
    ModelUsage,
    Notification,
    RiskSignal,
)
from agentgov.registry import features, findings

SYSTEM = "system:retention"
# Entries per archive, at most: a backlog is archived over several rounds.
ARCHIVE_BATCH = 50_000
# Checkpoints time-stamped per round, newest first.
STAMP_BATCH = 5
ARCHIVE_FAILED = "ledger.archive_failed"


class ArchiveError(Exception):
    """The ledger couldn't be archived (nowhere to write, or a broken chain)."""


# ------------------------------------------------------------------ checkpoints


def latest_checkpoint(session: Session) -> LedgerCheckpoint | None:
    return session.scalar(select(LedgerCheckpoint).order_by(LedgerCheckpoint.seq.desc()).limit(1))


def checkpoint_if_due(
    session: Session, settings: Settings, now: datetime | None = None
) -> LedgerCheckpoint | None:
    """Keep the head as a checkpoint when the last one is older than the period and the
    chain has grown since."""
    hours = settings.ledger_checkpoint_hours
    if hours <= 0:
        return None
    now = now or ids.utcnow()
    latest = latest_checkpoint(session)
    if latest is not None and latest.created_at > now - timedelta(hours=hours):
        return None
    point = ledger.checkpoint(session)
    if point is None or (latest is not None and point.seq == latest.seq):
        return None
    return point


def unstamped(session: Session) -> list[tuple[int, str]]:
    """Checkpoints still to be time-stamped, newest first."""
    rows = session.scalars(
        select(LedgerCheckpoint)
        .where(LedgerCheckpoint.timestamp.is_(None))
        .order_by(LedgerCheckpoint.seq.desc())
        .limit(STAMP_BATCH)
    )
    return [(c.seq, c.hash) for c in rows]


def save_stamp(
    session: Session,
    seq: int,
    url: str,
    *,
    response: bytes | None = None,
    time: datetime | None = None,
    error: str | None = None,
) -> None:
    point = session.get(LedgerCheckpoint, seq)
    if point is None:
        return
    point.tsa_url = url
    if response is not None:
        import base64

        point.timestamp = base64.b64encode(response).decode()
        point.timestamped_at, point.timestamp_error = time, None
    else:
        point.timestamp_error = error


# --------------------------------------------------------------------- archives


def _cursor_floor(session: Session) -> int | None:
    """The furthest entry every active destination has been sent, while they are sent to."""
    if features.mode(session, "security-operations") == features.OFF:
        return None
    cursors = session.scalars(
        select(Destination.cursor).where(Destination.status == "active")
    ).all()
    return min(cursors) if cursors else None


def archivable(session: Session, settings: Settings, now: datetime) -> tuple[int, int]:
    """The entries to archive now: after the chain's base, up to the last one older than
    the retention period whose predecessors are all older too, and no further than what
    every active destination has had."""
    floor, _ = ledger.base(session)
    cutoff = now - timedelta(days=settings.ledger_retention_days)
    young = session.scalar(
        select(func.min(LedgerEntry.seq)).where(LedgerEntry.seq > floor, LedgerEntry.ts >= cutoff)
    )
    head = session.get(LedgerHead, 1)
    last = (young - 1) if young is not None else (head.last_seq if head else floor)
    sent = _cursor_floor(session)
    if sent is not None:
        last = min(last, sent)
    return floor, min(last, floor + ARCHIVE_BATCH)


def archive(
    session: Session, settings: Settings, now: datetime | None = None
) -> dict[str, Any] | None:
    """Archive the entries past the retention period, then remove them from the database.
    None when there is nothing to archive (or retention is off)."""
    if settings.ledger_retention_days <= 0 or not settings.ledger_archive_dir:
        return None
    now = now or ids.utcnow()
    floor, last = archivable(session, settings, now)
    if last <= floor:
        return None
    directory = Path(settings.ledger_archive_dir)
    name = f"ledger-{floor + 1:012d}-{last:012d}.jsonl.gz"
    _, prev = ledger.base(session)
    tmp = directory / f".{name}.tmp"
    count, last_entry = 0, None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with gzip.open(tmp, "wt", encoding="utf-8") as out:
            for entry in ledger.iter_entries(session, after=floor, until=last):
                # A broken chain isn't archived over: the break stays where it can be seen.
                if entry.seq != floor + count + 1 or entry.prev_hash != prev:
                    raise ArchiveError(f"the chain is broken at entry {entry.seq}")
                if ledger.compute_hash(prev, entry) != entry.hash:
                    raise ArchiveError(f"entry {entry.seq} doesn't match its hash")
                out.write(json.dumps(ledger.to_dict(entry), sort_keys=True) + "\n")
                prev, last_entry, count = entry.hash, entry, count + 1
        if last_entry is None or last_entry.seq != last:
            raise ArchiveError(f"entries {floor + 1} to {last} aren't all there")
        with tmp.open("rb") as written:
            os.fsync(written.fileno())
        os.replace(tmp, directory / name)
        digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    except (OSError, ArchiveError) as exc:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        _archive_failed(session, str(exc))
        return {"error": str(exc)}
    point = session.get(LedgerCheckpoint, last) or LedgerCheckpoint(
        seq=last, hash=last_entry.hash, entry_ts=last_entry.ts
    )
    point.archive, point.archive_sha256 = name, digest
    point.archived_from, point.pruned_at = floor + 1, now
    session.add(point)
    session.flush()
    session.execute(delete(LedgerEntry).where(LedgerEntry.seq > floor, LedgerEntry.seq <= last))
    findings.resolve_key(session, f"{ARCHIVE_FAILED}:ledger", actor=SYSTEM)
    ledger.append(
        session,
        type="ledger.archived",
        actor=SYSTEM,
        reason=f"entries {floor + 1} to {last}, older than "
        f"{settings.ledger_retention_days} days, archived and removed",
        details={
            "from": floor + 1,
            "to": last,
            "entries": count,
            "archive": name,
            "sha256": digest,
            "hash": last_entry.hash,
        },
    )
    return {"from": floor + 1, "to": last, "entries": count, "archive": name, "sha256": digest}


def _archive_failed(session: Session, error: str) -> None:
    findings.raise_finding(
        session,
        type=ARCHIVE_FAILED,
        severity="high",
        subject="ledger",
        title="The ledger can't be archived: its old entries stay in the database",
        description=error,
        remediation="Fix what the error names: AGENTGOV_LEDGER_ARCHIVE_DIR must be writable "
        "by the control plane. A broken chain needs investigating before anything is "
        "archived (agentgov ledger verify).",
    )


def read_archive(path: str | Path) -> Any:
    """The entries in an archive (or an export), one dict per line."""
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as lines:
        for line in lines:
            if line.strip():
                yield json.loads(line)


# ---------------------------------------------------------------------- records


def prune_records(
    session: Session, settings: Settings, now: datetime | None = None
) -> dict[str, int]:
    """Remove the operational records older than AGENTGOV_DATA_RETENTION_DAYS."""
    days = settings.data_retention_days
    if days <= 0:
        return {}
    now = now or ids.utcnow()
    cutoff = now - timedelta(days=days)
    day = cutoff.strftime("%Y-%m-%d")
    gone_findings = select(Finding.id).where(
        Finding.status.in_(("resolved", "dismissed")), Finding.resolved_at < cutoff
    )
    statements = {
        "activity": delete(AgentActivity).where(AgentActivity.day < day),
        "model_usage": delete(ModelUsage).where(ModelUsage.day < day),
        "risk_signals": delete(RiskSignal).where(RiskSignal.ts < cutoff),
        "notifications": delete(Notification).where(
            or_(
                Notification.finding_id.in_(gone_findings),
                (Notification.status != "pending") & (Notification.created_at < cutoff),
            )
        ),
        "approvals": delete(ApprovalRequest).where(
            ApprovalRequest.status != "pending", ApprovalRequest.requested_at < cutoff
        ),
        "findings": delete(Finding).where(Finding.id.in_(gone_findings)),
        "access_assignments": delete(AccessAssignment).where(
            AccessAssignment.status.in_(("denied", "revoked", "renewed")),
            func.coalesce(AccessAssignment.ended_at, AccessAssignment.decided_at) < cutoff,
        ),
        "mcp_sightings": delete(McpSighting).where(McpSighting.last_seen_at < cutoff),
    }
    counts = {}
    for name, statement in statements.items():
        counts[name] = session.execute(
            statement.execution_options(synchronize_session=False)
        ).rowcount
    removed = {k: v for k, v in counts.items() if v}
    if removed:
        ledger.append(
            session,
            type="retention.pruned",
            actor=SYSTEM,
            reason=f"operational records older than {days} days removed",
            details={"before": ids.isoformat(cutoff), **removed},
        )
    return removed
