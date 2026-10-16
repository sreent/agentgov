"""A daily digest of their open issues, for each address and team chat that has some
(docs/issues.md#a-daily-digest): one message a day, at AGENTGOV_ISSUES_DIGEST_AT, with the
issues waiting for someone to take them on and those taken on, issues below the severity
sent one by one included. What went to whom each day is in the ledger.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from agentgov import db, ids, ledger
from agentgov.config import Settings
from agentgov.db import lock
from agentgov.db.models import SEVERITIES, Agent, Finding, IntegrationState
from agentgov.registry import finding_types, issues

STATE = "issues-digest"
# A message lists this many issues, the most pressing first, and counts the others.
LISTED = 25
# Tries to send each a day; after the last, it waits for the next day's.
MAX_TRIES = 6


@dataclass(frozen=True)
class Line:
    """An open issue, as a digest lists it."""

    finding_id: str
    title: str
    severity: str
    agent: str | None
    taken_on: bool
    # When it goes on to the next step of its chain unless someone acknowledges it.
    goes_further: datetime | None
    # First found since the last digest.
    new: bool


def due(settings: Settings, now: datetime) -> str | None:
    """The day whose digest is due, as a date where the digest's time zone is: once its
    time has come, on a day it goes out. None otherwise, and without a digest."""
    at = settings.digest_time()
    if at is None:
        return None
    local = now.astimezone(settings.digest_zone())
    if local.weekday() not in settings.digest_days() or (local.hour, local.minute) < at:
        return None
    return local.date().isoformat()


def start(tx: db.Transaction, day: str, now: datetime) -> dict[str, Any]:
    """The day's state: who has had it, and the tries for those who haven't. A new day
    starts afresh, remembering when the last one started."""
    row = IntegrationState.objects.filter(pk=STATE).first()
    if row is None:
        row = IntegrationState(key=STATE, data={})
    data = dict(row.data or {})
    if data.get("day") != day:
        data = {
            "day": day,
            "at": ids.isoformat(now),
            "previous": data.get("at"),
            "sent": [],
            "tries": {},
            "next": {},
        }
        row.data, row.updated_at = data, now
    row.save(force_insert=row._state.adding)
    return data


def _key(target: tuple[str, str]) -> str:
    return f"{target[0]} {target[1]}"


def waiting(state: dict[str, Any], target: tuple[str, str], now: datetime) -> bool:
    """Whether ``target`` (channel, recipient) is still to get the day's digest, now."""
    key = _key(target)
    if key in state.get("sent", []) or state.get("tries", {}).get(key, 0) >= MAX_TRIES:
        return False
    after = state.get("next", {}).get(key)
    return after is None or datetime.fromisoformat(after) <= now


def gather(
    tx: db.Transaction, settings: Settings, since: datetime
) -> dict[tuple[str, str], list[Line]]:
    """For each address and chat: the open issues with it now (those at the step of their
    chain it is at), those waiting for someone to take them on first, the most severe
    first."""
    directory = issues.Directory(tx)
    off = finding_types.off_types(tx)
    names: dict[str, str] = {}
    out: dict[tuple[str, str], list[Line]] = defaultdict(list)
    for finding in Finding.objects.filter(status="open", level__isnull=False):
        if finding.type in off:
            continue
        people = dict(issues.chain(tx, finding, directory)).get(finding.level or "")
        if not people:
            continue
        if finding.agent_id and finding.agent_id not in names:
            name = Agent.objects.filter(pk=finding.agent_id).values_list("name", flat=True).first()
            names[finding.agent_id] = name or finding.subject
        line = Line(
            finding_id=finding.id,
            title=finding.title,
            severity=finding.severity,
            agent=names.get(finding.agent_id or ""),
            taken_on=finding.acknowledged_at is not None,
            goes_further=None if finding.acknowledged_at else finding.escalate_at,
            new=finding.first_seen is not None and finding.first_seen > since,
        )
        for target in issues.addresses(tx, settings, people):
            out[target].append(line)
    for lines in out.values():
        lines.sort(key=lambda x: (x.taken_on, -SEVERITIES.index(x.severity), x.title))
    return dict(out)


def record(
    tx: db.Transaction,
    day: str,
    target: tuple[str, str],
    lines: list[Line],
    *,
    now: datetime,
    error: str | None = None,
) -> None:
    """Note that ``target`` had the day's digest, in the state and the ledger; or that it
    failed, to try again a little later (backing off), and in the ledger once it has
    failed for good."""
    from agentgov.secops.delivery import backoff

    row = IntegrationState.objects.filter(pk=STATE).first()
    if row is None:
        return
    lock(tx, row)
    data = dict(row.data or {})
    if data.get("day") != day:
        return
    key = _key(target)
    channel, to = target
    details = {
        "channel": channel,
        "to": to,
        "issues": len(lines),
        "waiting": sum(1 for x in lines if not x.taken_on),
    }
    if error is None:
        data["sent"] = [*data.get("sent", []), key]
        ledger.append(tx, type="issues.digest_sent", actor=issues.SYSTEM, details=details)
    else:
        tries = data.get("tries", {}).get(key, 0) + 1
        data["tries"] = {**data.get("tries", {}), key: tries}
        data["next"] = {**data.get("next", {}), key: ids.isoformat(now + backoff(tries))}
        if tries >= MAX_TRIES:
            ledger.append(
                tx,
                type="issues.digest_failed",
                actor=issues.SYSTEM,
                severity="warning",
                details={**details, "error": error[:500]},
            )
    row.data, row.updated_at = data, now
    row.save()


def since(state: dict[str, Any], now: datetime) -> datetime:
    """When the last digest went out (a day before now, before the first)."""
    previous = state.get("previous")
    return datetime.fromisoformat(previous) if previous else now - timedelta(days=1)
