"""Issues' tickets in service desks (docs/tickets.md): which issues get one, what the
desk is told as the issue goes on, and what AgentGov makes of what happens to it there.
The desks' APIs are agentgov.servicedesks; agentgov.ticketing runs the rounds.

* An issue gets a ticket in each active desk once it goes to someone, from the desk's
  minimum severity up (and, as for emails, not for what a platform's first sync found while
  AgentGov keeps those quiet). It goes to the group of the issue's team (the first team in
  its chain) or else the desk's own group; a desk may take only the issues of the teams it
  lists. Issues open when a desk is added get no ticket, unless it was added with backfill.
* The desk is told what changes: the issue going to the next people, someone taking it on
  in AgentGov, an exception asked for, its severity. When the issue ends (resolved,
  dismissed, its risk accepted), AgentGov resolves the ticket, or adds a note if the desk
  says not to.
* What happens in the desk comes back: a ticket assigned or worked on means someone took
  the issue on, so it goes no further up its chain. A ticket resolved there resolves a
  threat (an event someone dealt with; it opens again if it happens again). A posture
  issue is for AgentGov's own check to resolve: if it finds the problem again after the
  ticket was resolved, it opens another ticket that says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from agentgov import db, ids
from agentgov.config import Settings
from agentgov.db.models import SEVERITIES, Agent, Destination, Finding, Ticket
from agentgov.registry import desks, finding_types, findings, issues

SYSTEM = "system:tickets"
PENDING, OPEN, CLOSED, FAILED, SKIPPED = "pending", "open", "closed", "failed", "skipped"
STATUSES = (PENDING, OPEN, CLOSED, FAILED, SKIPPED)
# How the desk has it: nobody on it yet, someone on it, or over (resolved, closed, canceled).
NEW, ACTIVE, DONE = "new", "active", "done"
# Tried again after a failure, waiting longer each time (agentgov.secops.delivery.backoff),
# and given up on after about an hour.
MAX_ATTEMPTS = 13
# How often a ticket is read back from its desk.
READ_EVERY = timedelta(minutes=5)


def active_desks(tx: db.Transaction) -> list[Destination]:
    return list(Destination.objects.filter(kind__in=desks.DESKS, status="active").order_by("name"))


def team_of(tx: db.Transaction, finding: Finding, directory: issues.Directory) -> str | None:
    """The issue's team: the first team in its chain (its owner, a sponsor, or its team)."""
    for _level, people in issues.chain(tx, finding, directory):
        for person in people:
            if person.kind == "team":
                return person.name
    return None


def takes(settings: Settings, desk: Destination, finding: Finding, team: str | None) -> bool:
    """Whether this desk opens a ticket for the issue."""
    if finding.status != "open" or finding.level is None:
        return False
    if SEVERITIES.index(finding.severity) < SEVERITIES.index(desk.min_severity or "high"):
        return False
    if settings.issues_quiet_first_sync and (finding.details or {}).get(findings.BASELINE):
        return False
    return desks.takes(desk.tickets or {}, team)


def _new(desk: Destination, finding: Finding, team: str | None, status: str) -> Ticket:
    return Ticket(
        id=ids.new_id(ids.TICKET),
        finding_id=finding.id,
        destination_id=desk.id,
        round=finding.round or 0,
        team=team,
        status=status,
        phase=NEW,
        told={},
        attempts=0,
        next_attempt_at=ids.utcnow(),
    )


def plan(tx: db.Transaction, settings: Settings) -> int:
    """Tickets to open: for the open issues each desk takes that have none for their round
    (an open ticket of an earlier round follows the issue instead)."""
    chosen = active_desks(tx)
    if not chosen:
        return 0
    routed = list(Finding.objects.filter(status="open", level__isnull=False))
    if not routed:
        return 0
    off = finding_types.off_types(tx)
    had: set[tuple[str, str, int]] = set()
    live: set[tuple[str, str]] = set()
    for t in Ticket.objects.filter(finding_id__in=[f.id for f in routed]):
        had.add((t.finding_id, t.destination_id, t.round))
        if t.status in (PENDING, OPEN):
            live.add((t.finding_id, t.destination_id))
    directory = issues.Directory(tx)
    count = 0
    for finding in routed:
        if finding.type in off:
            continue
        team: str | None = None
        looked = False
        for desk in chosen:
            if (finding.id, desk.id, finding.round or 0) in had or (finding.id, desk.id) in live:
                continue
            if not looked:
                team, looked = team_of(tx, finding, directory), True
            if takes(settings, desk, finding, team):
                _new(desk, finding, team, PENDING).save(force_insert=True)
                count += 1
    return count


def skip_open(tx: db.Transaction, desk: Destination) -> int:
    """A desk just added: the issues already open get no ticket there (until they are
    raised again), so that it isn't flooded with what was there before it."""
    count = 0
    for finding in list(Finding.objects.filter(status="open", level__isnull=False)):
        _new(desk, finding, None, SKIPPED).save(force_insert=True)
        count += 1
    return count


def retry_failed(tx: db.Transaction, desk: Destination) -> int:
    """The desk's settings changed: what it refused is tried again now."""
    now = ids.utcnow()
    count = 0
    live = Ticket.objects.filter(destination_id=desk.id, status__in=(PENDING, OPEN, FAILED))
    for t in list(live):
        if t.status == FAILED:
            t.status, t.attempts = PENDING, 0
        if t.status == PENDING or t.last_error:
            t.next_attempt_at, t.last_error = now, None
            count += 1
        t.save()
    return count


def forget(tx: db.Transaction, desk: Destination) -> None:
    """The desk is deleted: AgentGov stops keeping its tickets in step (they stay there)."""
    Ticket.objects.filter(destination_id=desk.id).delete()


# ------------------------------------------------------------------ what to send


def link(settings: Settings, finding: Finding) -> str:
    return f"{settings.public_url.rstrip('/')}/ui/#/findings/{finding.id}"


@dataclass
class NewTicket:
    """What a desk is asked to open."""

    marker: str  # finds it again, should AgentGov not hear back that it was opened
    summary: str
    description: str  # the issue, with what agents, platforms and people wrote
    footer: str  # AgentGov's own words, with its link: the only text a desk may render
    severity: str
    group: str | int | None
    fields: dict[str, Any] = field(default_factory=dict)
    priority: dict[str, Any] = field(default_factory=dict)


def marker(ticket: Ticket) -> str:
    return f"agentgov-{ticket.id}"


def _about(tx: db.Transaction, finding: Finding, team: str | None) -> list[str]:
    from agentgov.registry.platforms import SOURCES

    agent = Agent.objects.filter(pk=finding.agent_id).first() if finding.agent_id else None
    facts = []
    if agent is not None:
        source = (agent.source or "").removeprefix("platform:")
        where = SOURCES.get(source) if agent.source != "registered" else None
        facts.append(f"Agent: {agent.name}" + (f" ({where})" if where else ""))
        if agent.owner:
            facts.append(f"Owner: {agent.owner}")
        if agent.sponsors:
            facts.append(f"Sponsors: {', '.join(str(s) for s in agent.sponsors)}")
    else:
        facts.append(f"About: {finding.subject}")
    if team:
        facts.append(f"Team: {team}")
    return facts


def new_ticket(
    tx: db.Transaction, settings: Settings, desk: Destination, ticket: Ticket, finding: Finding
) -> NewTicket:
    agent = Agent.objects.filter(pk=finding.agent_id).first() if finding.agent_id else None
    severity = finding.severity
    summary = f"[AgentGov] {severity.capitalize()}: {finding.title}"
    if agent is not None and agent.name not in finding.title:
        summary += f" ({agent.name})"
    lines = [finding.title, ""]
    if finding.description:
        lines += [finding.description, ""]
    if finding.remediation:
        lines += [f"What to do: {finding.remediation}", ""]
    lines += [
        " · ".join(_about(tx, finding, ticket.team)),
        f"Severity: {severity} · Kind: {finding.type} · First seen: "
        f"{ids.isoformat(finding.first_seen)}",
    ]
    if ticket.replaces:
        lines += [
            "",
            f"It takes over from {ticket.replaces}, which was resolved while AgentGov still "
            "finds the problem.",
        ]
    footer = (
        f"In AgentGov: {link(settings, finding)}\n\n"
        "AgentGov keeps this ticket in step with the issue: it adds a note when the issue "
        "changes, and resolves the ticket once the problem is gone. Assigning the ticket, or "
        "starting work on it, tells AgentGov that someone has taken the issue on. To accept "
        "the risk instead of fixing it, ask for that in AgentGov: an approver decides."
    )
    cfg = desk.tickets or {}
    return NewTicket(
        marker=marker(ticket),
        # One line: a desk refuses a summary that breaks (Jira does).
        summary=" ".join(summary.split()),
        description="\n".join(lines),
        footer=footer,
        severity=severity,
        group=desks.group_for(cfg, ticket.team),
        fields=dict(cfg.get("fields") or {}),
        priority=desks.priorities(desk.kind, cfg, severity),
    )


def snapshot(finding: Finding) -> dict[str, Any]:
    """What a ticket is told of its issue: only changes to this are sent."""
    return {
        "round": finding.round or 0,
        "status": finding.status,
        "severity": finding.severity,
        "level": finding.level,
        "ack": finding.acknowledged_at is not None,
        "asked": bool((finding.details or {}).get(issues.ASKED)),
    }


@dataclass
class Work:
    """What to tell a desk about a ticket's issue."""

    notes: list[str] = field(default_factory=list)
    severity: str | None = None  # its priority follows this severity now
    ended: str | None = None  # the issue ended: why (the ticket is resolved, or noted)
    let_go: bool = False  # done in the desk and the issue raised again: another opens
    state: dict[str, Any] = field(default_factory=dict)  # the issue, as this tells it

    def __bool__(self) -> bool:
        return bool(self.notes or self.severity or self.ended or self.let_go)


def _date(value: Any) -> str:
    text = ids.isoformat(value) if isinstance(value, datetime) else str(value or "")
    return text[:10]


def _ended(finding: Finding) -> str:
    details = finding.details or {}
    if finding.status == "accepted":
        return (
            f"Its risk was accepted in AgentGov until {_date(finding.accepted_until)}: "
            f"{finding.accepted_reason or 'no reason given'}. If the problem is still there "
            "then, the issue opens again."
        )
    if finding.status == "dismissed":
        if finding_types.SUPPRESSED in details:
            return "AgentGov no longer raises this kind of issue: an administrator turned it off."
        dismissal = details.get(findings.DISMISSAL) or {}
        until = f" (until {_date(dismissal['until'])})" if dismissal.get("until") else ""
        return (
            f"{dismissal.get('by') or finding.resolved_by or 'Someone'} dismissed the issue in "
            f"AgentGov{until}: {dismissal.get('reason') or 'no reason given'}."
        )
    who = finding.resolved_by or ""
    if not who or who.startswith("system:"):
        return "AgentGov no longer finds the problem, so the issue is resolved."
    return f"{who} resolved the issue in AgentGov."


def work(ticket: Ticket, finding: Finding) -> Work:
    """What changed in the issue since the ticket was last told."""
    told = ticket.told or {}
    todo = Work(state=snapshot(finding))
    if finding.status != "open":
        if told.get("status", "open") == "open":
            todo.ended = _ended(finding)
        return todo
    if (finding.round or 0) != ticket.round:
        if ticket.phase == DONE:
            todo.let_go = True
            return todo
        worse = SEVERITIES.index(finding.severity) > SEVERITIES.index(
            told.get("severity", finding.severity)
        )
        todo.notes.append(
            f"Its severity rose to {finding.severity}: AgentGov tells its people again."
            if worse
            else "The problem came back: AgentGov raised the issue again."
        )
        if finding.severity != told.get("severity"):
            todo.severity = finding.severity
        return todo
    if told.get("severity") and finding.severity != told["severity"]:
        todo.severity = finding.severity
        todo.notes.append(f"Its severity changed from {told['severity']} to {finding.severity}.")
    if finding.level and finding.level != told.get("level") and finding.acknowledged_at is None:
        whom = ", ".join(finding.assignees or []) or "nobody"
        todo.notes.append(
            f"Nobody took it on in time: it now goes to {whom}, as its {finding.level}."
        )
    if finding.acknowledged_at is not None and not told.get("ack"):
        todo.notes.append(f"{finding.acknowledged_by or 'Someone'} took it on in AgentGov.")
    asked = (finding.details or {}).get(issues.ASKED)
    if asked and not told.get("asked"):
        todo.notes.append(
            f"{asked.get('by', 'Someone')} asked for its risk to be accepted until "
            f"{_date(asked.get('until'))}: {asked.get('reason', '')}. An approver decides in "
            "AgentGov."
        )
    return todo


# ------------------------------------------------------------------ what comes back


@dataclass
class Seen:
    """A ticket as its desk has it."""

    state: str  # as the desk names it
    phase: str  # NEW, ACTIVE or DONE
    assignee: str | None = None
    resolution: str | None = None


def actor(desk: Destination, ticket: Ticket) -> str:
    return f"{desk.kind}:{ticket.key or ticket.id}"


def _who(desk: Destination, ticket: Ticket, seen: Seen) -> str:
    where = f"{desk.name} {ticket.key}"
    return f"{seen.assignee} ({where})" if seen.assignee else where


def seen(
    tx: db.Transaction,
    settings: Settings,
    desk: Destination,
    ticket: Ticket,
    finding: Finding,
    what: Seen,
    now: datetime,
) -> list[str]:
    """Record what the desk says of a ticket, and what it means for the issue; returns what
    happened, in words."""
    happened = _seen(tx, desk, ticket, finding, what, now)
    ticket.save()
    finding.save()
    return happened


def _seen(
    tx: db.Transaction,
    desk: Destination,
    ticket: Ticket,
    finding: Finding,
    what: Seen,
    now: datetime,
) -> list[str]:
    happened = []
    ticket.state, ticket.phase, ticket.assignee = what.state[:64], what.phase, what.assignee
    ticket.synced_at = now
    if what.phase != DONE and ticket.done_seen_at is not None:
        ticket.done_seen_at = None  # opened again there
    if finding.status != "open":
        return happened
    if (what.phase != NEW or what.assignee) and finding.acknowledged_at is None:
        finding.acknowledged_at = now
        finding.acknowledged_by = _who(desk, ticket, what)[:200]
        finding.escalate_at = None
        findings.record(
            tx,
            finding,
            "acknowledged",
            actor(desk, ticket),
            severity="info",
            ticket=ticket.key,
            desk=desk.name,
            by=what.assignee,
        )
        ticket.told = {**(ticket.told or {}), "ack": True}
        happened.append("taken on")
    if what.phase != DONE:
        return happened
    if ticket.done_seen_at is None:
        ticket.done_seen_at = now
        findings.record(
            tx,
            finding,
            "ticket_done",
            actor(desk, ticket),
            severity="info",
            ticket=ticket.key,
            desk=desk.name,
            state=what.state,
            by=what.assignee,
            **({"resolution": what.resolution} if what.resolution else {}),
        )
        happened.append("done in the desk")
        if finding.category == findings.THREAT:
            # An event someone dealt with: it opens again if it happens again.
            finding.status = "resolved"
            finding.resolved_at = now
            finding.resolved_by = _who(desk, ticket, what)[:200]
            finding.escalate_at = None
            findings.record(
                tx,
                finding,
                "resolved",
                actor(desk, ticket),
                why=f"resolved in {desk.name} ({ticket.key})",
            )
            ticket.told = {**(ticket.told or {}), "status": "resolved"}
            ticket.status = CLOSED
            happened.append("resolved")
        return happened
    if finding.category != findings.THREAT and finding.last_seen > ticket.done_seen_at:
        # Resolved there, but AgentGov's check found the problem again since: another
        # ticket says so.
        ticket.status = CLOSED
        again = _new(desk, finding, ticket.team, PENDING)
        again.replaces = ticket.key
        again.save(force_insert=True)
        happened.append("replaced")
    return happened


def opened(
    tx: db.Transaction,
    desk: Destination,
    ticket: Ticket,
    finding: Finding | None,
    *,
    key: str,
    remote_id: str,
    url: str | None,
    state: dict[str, Any],
) -> None:
    """It is open in the desk, telling the issue as ``state`` (its snapshot when the ticket
    was written): what changed since is sent next."""
    ticket.status = OPEN
    ticket.key, ticket.remote_id, ticket.url = key[:64], remote_id[:64], url
    ticket.attempts, ticket.last_error = 0, None
    ticket.next_attempt_at = ids.utcnow()
    ticket.told = state
    ticket.round = state.get("round", ticket.round)
    ticket.save()
    if finding is None:
        return
    findings.record(
        tx,
        finding,
        "ticket_opened",
        SYSTEM,
        severity="info",
        ticket=key,
        desk=desk.name,
        url=url,
        **({"replaces": ticket.replaces} if ticket.replaces else {}),
    )


def failed(
    tx: db.Transaction, desk: Destination, ticket: Ticket, finding: Finding | None, error: str
) -> None:
    """It couldn't go: tried again later, until it is given up on."""
    from agentgov.secops.delivery import backoff

    ticket.attempts += 1
    ticket.last_error = error[:1000]
    if ticket.status == PENDING and ticket.attempts >= MAX_ATTEMPTS:
        ticket.status = FAILED
        ticket.save()
        if finding is not None:
            findings.record(
                tx,
                finding,
                "ticket_failed",
                SYSTEM,
                severity="warning",
                desk=desk.name,
                error=ticket.last_error,
            )
        return
    ticket.next_attempt_at = ids.utcnow() + backoff(ticket.attempts)
    ticket.save()


def told(
    tx: db.Transaction, desk: Destination, ticket: Ticket, finding: Finding, done: Work
) -> None:
    """The desk has what changed (as ``done`` told it: what changed since goes next)."""
    ticket.told = done.state
    ticket.round = done.state.get("round", ticket.round)
    ticket.attempts, ticket.last_error = 0, None
    if done.let_go:
        ticket.status = CLOSED
        ticket.save()
        return
    if done.ended:
        ticket.status = CLOSED
        findings.record(
            tx,
            finding,
            "ticket_closed",
            SYSTEM,
            severity="info",
            ticket=ticket.key,
            desk=desk.name,
            resolved=ticket.phase != DONE and desks.resolves(desk.tickets or {}),
        )
    ticket.save()


# ------------------------------------------------------------------ what people see


def to_dict(t: Ticket, desk: Destination | None) -> dict[str, Any]:
    waiting = t.status == PENDING or (t.status == OPEN and t.last_error)
    return {
        "id": t.id,
        "finding_id": t.finding_id,
        "desk": desk.name if desk else None,
        "kind": desk.kind if desk else None,
        "key": t.key,
        "url": t.url,
        "status": t.status,
        "state": t.state,
        "phase": t.phase,
        "assignee": t.assignee,
        "team": t.team,
        "round": t.round,
        "replaces": t.replaces,
        "attempts": t.attempts,
        "last_error": t.last_error,
        "next_attempt_at": ids.isoformat(t.next_attempt_at) if waiting else None,
        "synced_at": ids.isoformat(t.synced_at),
        "created_at": ids.isoformat(t.created_at),
    }


def for_finding(tx: db.Transaction, finding: Finding) -> list[dict[str, Any]]:
    rows = list(
        Ticket.objects.filter(finding_id=finding.id).exclude(status=SKIPPED).order_by("created_at")
    )
    named = {d.id: d for d in Destination.objects.all()}
    return [to_dict(t, named.get(t.destination_id)) for t in rows]


def listing(
    tx: db.Transaction, *, desk: str | None = None, status: str | None = None, limit: int = 500
) -> list[dict[str, Any]]:
    named = {d.id: d for d in Destination.objects.all()}
    rows = Ticket.objects.exclude(status=SKIPPED).order_by("-created_at")
    if desk:
        rows = rows.filter(destination_id__in=[i for i, d in named.items() if desk in (d.name, i)])
    if status:
        rows = rows.filter(status=status)
    return [to_dict(t, named.get(t.destination_id)) for t in rows[:limit]]


def counts(tx: db.Transaction) -> dict[str, dict[str, int]]:
    """By desk: its tickets AgentGov keeps in step, those waiting to open, those it gave up
    opening, and those whose last try failed."""
    out: dict[str, dict[str, int]] = {}
    for t in Ticket.objects.filter(status__in=(PENDING, OPEN, FAILED)):
        row = out.setdefault(t.destination_id, {"open": 0, "pending": 0, "failed": 0, "erring": 0})
        row[t.status] += 1
        if t.last_error:
            row["erring"] += 1
    return out
