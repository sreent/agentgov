"""How long AgentGov keeps what it records (docs/evidence.md).

The ledger is evidence: nothing leaves it unarchived. Every
``AGENTGOV_LEDGER_CHECKPOINT_HOURS`` its head is kept as a checkpoint, which a
time-stamping authority signs when ``AGENTGOV_LEDGER_TSA_URL`` is set
(agentgov.timestamping), and which goes into a transparency log when
``AGENTGOV_LEDGER_REKOR_URL`` is (agentgov.transparency). With
``AGENTGOV_LEDGER_RETENTION_DAYS``, entries older than that are written to an archive in
``AGENTGOV_LEDGER_ARCHIVE_DIR`` (gzipped JSON Lines, checked link by link as they are
written), a checkpoint records the archive and its SHA-256, and only then do the entries
leave the database: the chain there goes on from that checkpoint, and the archive
verifies offline (``agentgov ledger verify --file``).
Entries an active destination hasn't been sent yet stay, while security operations are on.

The operational records whose history is in the ledger (daily activity and model usage,
risk signals, notifications sent, decided approval requests, resolved findings, ended
access assignments, developers' MCP servers not reported since) go after
``AGENTGOV_DATA_RETENTION_DAYS``.

The functions here run in the caller's transaction (agentgov.db), on Django's ORM.
"""

from __future__ import annotations

import base64
import contextlib
import gzip
import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from django.db.models import Min, Q

from agentgov import db, ids, ledger, timestamping
from agentgov.config import Settings
from agentgov.db.models import (
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


def latest_checkpoint(tx: db.Where) -> LedgerCheckpoint | None:
    return LedgerCheckpoint.objects.order_by("-seq").first()


def checkpoint_if_due(
    tx: db.Where, settings: Settings, now: datetime | None = None
) -> LedgerCheckpoint | None:
    """Keep the head as a checkpoint when the last one is older than the period and the
    chain has grown since."""
    hours = settings.ledger_checkpoint_hours
    if hours <= 0:
        return None
    now = now or ids.utcnow()
    latest = latest_checkpoint(tx)
    if latest is not None and latest.created_at > now - timedelta(hours=hours):
        return None
    point = ledger.checkpoint(tx)
    if point is None or (latest is not None and point.seq == latest.seq):
        return None
    return point


def unstamped(tx: db.Where) -> list[tuple[int, str]]:
    """Checkpoints still to be time-stamped, newest first."""
    rows = LedgerCheckpoint.objects.filter(timestamp__isnull=True).order_by("-seq")
    return list(rows.values_list("seq", "hash")[:STAMP_BATCH])


def save_stamp(
    tx: db.Where,
    seq: int,
    url: str,
    *,
    stamp: timestamping.Stamp | None = None,
    error: str | None = None,
) -> None:
    """Keep the authority's time-stamp on the checkpoint, and record it in the chain, so
    that one taken away or replaced later shows (agentgov.ledger.verify); or why there is
    none yet."""
    point = LedgerCheckpoint.objects.filter(seq=seq).first()
    if point is None:
        return
    point.tsa_url = url
    if stamp is None:
        point.timestamp_error = error
        point.save(update_fields=["tsa_url", "timestamp_error"])
        return
    point.timestamp = base64.b64encode(stamp.response).decode()
    point.timestamped_at, point.timestamp_error = stamp.time, None
    point.save(update_fields=["tsa_url", "timestamp", "timestamped_at", "timestamp_error"])
    ledger.append(
        tx,
        type=ledger.STAMPED,
        actor=SYSTEM,
        reason=f"checkpoint {seq} time-stamped by {url}",
        details={
            "checkpoint": seq,
            "hash": point.hash,
            "token": hashlib.sha256(stamp.response).hexdigest(),
            "time": ids.isoformat(stamp.time),
            "tsa": url,
            # Its signature checked against the authority's certificates, or only against
            # the one it carries.
            "authority": stamp.authority,
        },
    )


def unlogged(tx: db.Where) -> list[tuple[int, str]]:
    """Checkpoints still to be added to the transparency log, newest first (one that the
    log took, and whose proof didn't check out, isn't added again)."""
    rows = LedgerCheckpoint.objects.filter(tlog_entry__isnull=True).order_by("-seq")
    return list(rows.values_list("seq", "hash")[:STAMP_BATCH])


def save_log_entry(
    tx: db.Where,
    seq: int,
    url: str,
    *,
    entry: dict[str, Any] | None = None,
    checked: bool | None = None,
    error: str | None = None,
) -> None:
    values: dict[str, Any] = {"tlog_url": url, "tlog_error": error}
    if entry is not None:
        values.update(
            tlog_entry=entry,
            tlog_index=int(entry["logIndex"]),
            tlog_logged_at=ids.utcnow(),
            tlog_checked=checked,
        )
    LedgerCheckpoint.objects.filter(seq=seq).update(**values)


# --------------------------------------------------------------------- archives


def _cursor_floor(tx: db.Where) -> int | None:
    """The furthest entry every active destination has been sent, while they are sent to."""
    if features.mode(tx, "security-operations") == features.OFF:
        return None
    cursors = Destination.objects.filter(status="active").values_list("cursor", flat=True)
    return min(cursors, default=None)


def archivable(tx: db.Where, settings: Settings, now: datetime) -> tuple[int, int]:
    """The entries to archive now: after the chain's base, up to the last one older than
    the retention period whose predecessors are all older too, and no further than what
    every active destination has had."""
    floor, _ = ledger.base(tx)
    cutoff = now - timedelta(days=settings.ledger_retention_days)
    young = ledger.chain().filter(seq__gt=floor, ts__gte=cutoff).aggregate(seq=Min("seq"))["seq"]
    head = LedgerHead.objects.filter(id=1).values_list("last_seq", flat=True).first()
    end = head if head is not None else floor
    last = min((young - 1) if young is not None else end, end)
    sent = _cursor_floor(tx)
    if sent is not None:
        last = min(last, sent)
    return floor, min(last, floor + ARCHIVE_BATCH)


def archive(tx: db.Where, settings: Settings, now: datetime | None = None) -> dict[str, Any] | None:
    """Archive the entries past the retention period, then remove them from the database.
    None when there is nothing to archive (or retention is off)."""
    if settings.ledger_retention_days <= 0 or not settings.ledger_archive_dir:
        return None
    now = now or ids.utcnow()
    floor, last = archivable(tx, settings, now)
    if last <= floor:
        return None
    directory = Path(settings.ledger_archive_dir)
    name = f"ledger-{floor + 1:012d}-{last:012d}.jsonl.gz"
    _, prev = ledger.base(tx)
    follows = prev
    tmp = directory / f".{name}.tmp"
    count, last_entry = 0, None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with gzip.open(tmp, "wt", encoding="utf-8") as out:
            for entry in ledger.iter_entries(tx, after=floor, until=last):
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
        target = directory / name
        if target.exists():
            # Archives are evidence, never written over: one already there holds these
            # entries (a round that didn't finish), or it is left as it is and nothing goes.
            if not _same_entries(target, tmp):
                raise ArchiveError(
                    f"an archive {name} is already there, holding other entries: it is left as "
                    "it is, and nothing is archived until someone finds out why"
                )
            tmp.unlink()
        else:
            os.replace(tmp, target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
    except (OSError, ArchiveError) as exc:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        _archive_failed(tx, str(exc))
        return {"error": str(exc)}
    point = LedgerCheckpoint.objects.filter(seq=last).first() or LedgerCheckpoint(
        seq=last, hash=last_entry.hash, entry_ts=last_entry.ts
    )
    point.archive, point.archive_sha256 = name, digest
    point.archived_from, point.pruned_at = floor + 1, now
    point.save()
    LedgerEntry.objects.filter(seq__gt=floor, seq__lte=last).delete()
    findings.resolve_key(tx, f"{ARCHIVE_FAILED}:ledger", actor=SYSTEM)
    ledger.append(
        tx,
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
            # The hash the first entry goes on from: the archive before's last, so that
            # the chain itself says where the archive starts, as well as where it ends.
            "follows": follows,
        },
    )
    return {"from": floor + 1, "to": last, "entries": count, "archive": name, "sha256": digest}


def _same_entries(one: Path, other: Path) -> bool:
    """Whether two archives hold the same entries, however they were compressed."""

    def entries(path: Path) -> list[Any]:
        with gzip.open(path, "rt", encoding="utf-8") as lines:
            return [json.loads(line) for line in lines if line.strip()]

    try:
        return entries(one) == entries(other)
    except (OSError, EOFError, ValueError):
        return False


def _archive_failed(tx: db.Where, error: str) -> None:
    findings.raise_finding(
        tx,
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


def prune_records(tx: db.Where, settings: Settings, now: datetime | None = None) -> dict[str, int]:
    """Remove the operational records older than AGENTGOV_DATA_RETENTION_DAYS."""
    days = settings.data_retention_days
    if days <= 0:
        return {}
    now = now or ids.utcnow()
    cutoff = now - timedelta(days=days)
    day = cutoff.strftime("%Y-%m-%d")
    gone_findings = Finding.objects.filter(
        status__in=("resolved", "dismissed"), resolved_at__lt=cutoff
    ).values("id")
    ended = Q(ended_at__lt=cutoff) | Q(ended_at__isnull=True, decided_at__lt=cutoff)
    records = {
        "activity": AgentActivity.objects.filter(day__lt=day),
        "model_usage": ModelUsage.objects.filter(day__lt=day),
        "risk_signals": RiskSignal.objects.filter(ts__lt=cutoff),
        "notifications": Notification.objects.filter(
            Q(finding_id__in=gone_findings) | (~Q(status="pending") & Q(created_at__lt=cutoff))
        ),
        "approvals": ApprovalRequest.objects.exclude(status="pending").filter(
            requested_at__lt=cutoff
        ),
        "findings": Finding.objects.filter(id__in=gone_findings),
        "access_assignments": AccessAssignment.objects.filter(
            ended, status__in=("denied", "revoked", "renewed")
        ),
        "mcp_sightings": McpSighting.objects.filter(last_seen_at__lt=cutoff),
    }
    counts = {name: rows.delete()[0] for name, rows in records.items()}
    removed = {k: v for k, v in counts.items() if v}
    if removed:
        ledger.append(
            tx,
            type="retention.pruned",
            actor=SYSTEM,
            reason=f"operational records older than {days} days removed",
            details={"before": ids.isoformat(cutoff), **removed},
        )
    return removed
