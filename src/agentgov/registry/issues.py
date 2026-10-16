"""Issues: findings routed to the people responsible for them (docs/issues.md).

A finding about an agent goes to its owner first, then its sponsors, then its team (its
own, its blueprint's, or the default team); one about a tool server to its owner, then the
default team; any other to the default team. An owner or a sponsor is a person (an email
address or a user name) or a team, by name. At each step, AgentGov tells the people and
teams there, by email and in their teams' chats, and lists the issue for them in AgentGov.
If none of them acknowledges it in time (AGENTGOV_ISSUE_ESCALATION_HOURS), it goes to the
next step. Acknowledging stops it there; resolving it, or accepting the risk until a date,
ends it. Raised again later, it starts over.

Nothing is routed or sent while the issues feature is off; findings stay in AgentGov's
list as before.

The functions here run in the caller's transaction (agentgov.db), on Django's ORM.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from agentgov import db, ids, ledger
from agentgov.config import Settings
from agentgov.db import lock
from agentgov.db.models import (
    Agent,
    Destination,
    Finding,
    LedgerEntry,
    Notification,
    ToolServer,
)
from agentgov.models import SEVERITIES
from agentgov.registry import finding_types, findings, teams
from agentgov.registry import people as directory_people
from agentgov.registry.errors import Forbidden, InvalidTransition, ValidationError

OWNER, SPONSORS, TEAM = "owner", "sponsors", "team"
LEVELS = (OWNER, SPONSORS, TEAM)
SYSTEM = "system:issues"
# Someone it reached asks for its risk to be accepted (docs/issues.md#answering-an-issue):
# who, why and until when, in the finding's details until an approver decides.
ASKED = "exception_request"
# The longest a risk can be accepted for: then someone decides again.
MAX_ACCEPT = timedelta(days=365)
EMAIL = "email"


@dataclass(frozen=True)
class Recipient:
    """A person or a team at a step of an issue's chain, and how they are reached."""

    kind: str  # "person" or "team"
    name: str  # an email address or a user name; or the team's name
    emails: tuple[str, ...] = ()
    channels: tuple[str, ...] = ()  # Teams and Slack destinations, by name
    members: tuple[str, ...] = ()  # a team's people, by email address or user name

    def describe(self) -> str:
        return f"team {self.name}" if self.kind == "team" else self.name


class Directory:
    """The teams, read once for a round of routing or a list of issues."""

    def __init__(self, tx: db.Where) -> None:
        self.teams = {t.name: t for t in teams.list_all(tx)}
        self.default = next((t for t in self.teams.values() if t.is_default), None)
        # People who left: an issue goes past them (docs/issues.md#people-who-leave).
        self.left = set(directory_people.gone(tx))

    def recipient(self, name: str | None) -> Recipient | None:
        """Who a name stands for: a team of that name, or else a person."""
        name = (name or "").strip()
        if not name:
            return None
        team = self.teams.get(name)
        if team is not None:
            members = tuple(team.members or [])
            # Its own addresses, or else its members'.
            emails = tuple(team.emails or []) or tuple(m for m in members if teams.is_email(m))
            return Recipient("team", team.name, emails, tuple(team.destinations or []), members)
        if name.lower() in self.left:
            return None  # gone: the next step takes it
        if teams.is_email(name):
            return Recipient("person", name.lower(), (name.lower(),))
        # Reached in AgentGov only, when they sign in.
        return Recipient("person", name)

    def team(self, *names: str | None) -> Recipient | None:
        """The first of these that is a team, or else the default team."""
        for name in names:
            if name and name in self.teams:
                return self.recipient(name)
        return self.recipient(self.default.name) if self.default else None


def _server(tx: db.Where, subject: str | None) -> ToolServer | None:
    """The tool server an issue is about: its subject is the server (by ID or name), or one
    of its tools ("crm/export_customers")."""
    ref = (subject or "").split("/", 1)[0]
    if not ref:
        return None
    return ToolServer.objects.filter(pk=ref).first() or ToolServer.objects.filter(name=ref).first()


def _agent(finding: Finding) -> Agent | None:
    """The agent a finding is about, if any."""
    if not finding.agent_id:
        return None
    return Agent.objects.select_related("blueprint").filter(pk=finding.agent_id).first()


def chain(
    tx: db.Where, finding: Finding, directory: Directory | None = None
) -> list[tuple[str, list[Recipient]]]:
    """The steps of a finding's chain, each with the people and teams at it that no earlier
    step reached. Steps with nobody new at them are left out."""
    d = directory or Directory(tx)
    raw: list[tuple[str, list[Recipient | None]]] = []
    agent = _agent(finding)
    if agent is not None:
        blueprint = agent.blueprint
        raw = [
            (OWNER, [d.recipient(agent.owner)]),
            (SPONSORS, [d.recipient(str(s)) for s in agent.sponsors or []]),
            (TEAM, [d.team(agent.team, blueprint.team if blueprint else None)]),
        ]
    elif finding.type.startswith("toolserver."):
        server = _server(tx, finding.subject)
        raw = [(OWNER, [d.recipient(server.owner) if server else None]), (TEAM, [d.team()])]
    else:
        raw = [(TEAM, [d.team()])]
    steps: list[tuple[str, list[Recipient]]] = []
    reached: set[str] = set()
    for level, people in raw:
        new = [
            p for p in dict.fromkeys(p for p in people if p is not None) if p.name not in reached
        ]
        if new:
            steps.append((level, new))
            reached.update(p.name for p in new)
    return steps


def involved(tx: db.Where, finding: Finding, directory: Directory | None = None) -> set[str]:
    """Everyone the issue has reached so far, by email address and user name (lower case),
    team members included: they may see it and acknowledge it."""
    names: set[str] = set()
    if finding.level is None:
        return names
    for level, people in chain(tx, finding, directory):
        for person in people:
            if person.kind == "person":
                names.add(person.name.lower())
            # A team by its members and addresses, never its name: a person could have it.
            names.update(e.lower() for e in (*person.emails, *person.members))
        if level == finding.level:
            break
    return names


def _next(
    steps: list[tuple[str, list[Recipient]]], level: str | None
) -> tuple[str, list[Recipient]] | None:
    """The step after ``level`` (the first, without one)."""
    if level is None:
        return steps[0] if steps else None
    later = [s for s in steps if LEVELS.index(s[0]) > LEVELS.index(level)]
    return later[0] if later else None


def _give(
    tx: db.Where,
    settings: Settings,
    finding: Finding,
    step: tuple[str, list[Recipient]],
    steps: list[tuple[str, list[Recipient]]],
    now: datetime,
    *,
    escalated: bool,
) -> None:
    level, people = step
    finding.level = level
    finding.assignees = [p.describe() for p in people]
    hours = settings.escalation_delays()[finding.severity]
    finding.escalate_at = now + timedelta(hours=hours) if _next(steps, level) else None
    finding.save()
    quiet = _quiet(settings, finding)
    queued = 0 if quiet else _queue(tx, settings, finding, level, people)
    findings.record(
        tx,
        finding,
        "escalated" if escalated else "assigned",
        SYSTEM,
        severity="warning" if escalated else "info",
        level=level,
        assignees=finding.assignees,
        notifications=queued,
        **({"quiet": quiet} if quiet else {}),
    )


def _quiet(settings: Settings, finding: Finding) -> str | None:
    """Why no email or chat message goes out for it, if none does: the people it is with
    see it in AgentGov all the same."""
    floor = settings.issues_notify_severity
    if SEVERITIES.index(finding.severity) < SEVERITIES.index(floor):
        return f"below {floor}, the severity that is sent"
    if settings.issues_quiet_first_sync and (finding.details or {}).get(findings.BASELINE):
        return "found by its platform's first sync"
    return None


def addresses(tx: db.Where, settings: Settings, people: list[Recipient]) -> list[tuple[str, str]]:
    """Where messages for these people and teams go, as (channel, recipient): email to
    their addresses (with a mail server), and their teams' chats."""
    wanted: list[tuple[str, str]] = []
    for person in people:
        if settings.smtp_url:
            wanted += [(EMAIL, address) for address in person.emails]
        for name in person.channels:
            kind = Destination.objects.filter(name=name).values_list("kind", flat=True).first()
            if kind is not None:
                wanted.append((kind, name))
    return list(dict.fromkeys(wanted))


def _queue(
    tx: db.Where, settings: Settings, finding: Finding, level: str, people: list[Recipient]
) -> int:
    """Queue the messages for the people at this step."""
    count = 0
    for channel, to in addresses(tx, settings, people):
        sent = Notification.objects.filter(
            finding_id=finding.id,
            round=finding.round,
            level=level,
            channel=channel,
            recipient=to,
        )
        if sent.exists():
            continue
        Notification.objects.create(
            id=ids.new_id(ids.NOTIFICATION),
            finding_id=finding.id,
            round=finding.round or 0,
            level=level,
            channel=channel,
            recipient=to,
            status="pending",
            attempts=0,
            next_attempt_at=ids.utcnow(),
        )
        count += 1
    return count


# ------------------------------------------------------------------------ rounds


def route(tx: db.Where, settings: Settings, now: datetime | None = None) -> dict[str, int]:
    """Give open findings that aren't with anyone to the first step of their chain, and
    escalate those nobody acknowledged in time."""
    now = now or ids.utcnow()
    assigned = escalated = 0
    directory = Directory(tx)
    off = finding_types.off_types(tx)
    for finding in list(Finding.objects.filter(status="open")):
        if finding.type in off:
            continue  # reopened by hand while its type is off: nobody is told
        steps = chain(tx, finding, directory)
        if finding.level is None:
            first = _next(steps, None)
            if first is not None:
                _give(tx, settings, finding, first, steps, now, escalated=False)
                assigned += 1
        elif (
            finding.acknowledged_at is None
            and finding.escalate_at is not None
            and finding.escalate_at <= now
        ):
            step = _next(steps, finding.level)
            if step is None:
                finding.escalate_at = None
                finding.save()
            else:
                _give(tx, settings, finding, step, steps, now, escalated=True)
                escalated += 1
    return {"assigned": assigned, "escalated": escalated}


def reopen_accepted(tx: db.Where, now: datetime | None = None) -> int:
    """Accepted risks, and dismissals given until a date, whose date has come open again,
    for someone to decide anew. If the condition is gone, the next check resolves them."""
    now = now or ids.utcnow()
    count = 0
    off = finding_types.off_types(tx)
    for finding in list(Finding.objects.filter(status="dismissed")):
        until = ((finding.details or {}).get(findings.DISMISSAL) or {}).get("until")
        if not until or datetime.fromisoformat(until) > now or finding.type in off:
            continue
        finding.status = "open"
        finding.resolved_at = finding.resolved_by = None
        finding.details = {
            k: v for k, v in (finding.details or {}).items() if k != findings.DISMISSAL
        }
        findings.restart_chain(finding)
        finding.save()
        findings.record(
            tx, finding, "reopened", SYSTEM, why="the time it was dismissed for ran out"
        )
        count += 1
    for finding in list(Finding.objects.filter(status="accepted", accepted_until__lte=now)):
        if finding.type in off:
            finding_types.suppress(finding, now)
            finding.save()
            continue
        finding.status = "open"
        finding.accepted_until = None
        findings.restart_chain(finding)
        finding.save()
        findings.record(
            tx, finding, "reopened", SYSTEM, why="the time its risk was accepted for ran out"
        )
        count += 1
    return count


# ---------------------------------------------------------------------- actions


def acknowledge(tx: db.Where, finding: Finding, *, actor: str) -> Finding:
    """Someone it reached takes it on: it stops going further up its chain."""
    lock(tx, finding)
    if finding.status != "open":
        raise InvalidTransition(f"finding is {finding.status}: only open findings are acknowledged")
    if finding.acknowledged_at is None:
        finding.acknowledged_at = ids.utcnow()
        finding.acknowledged_by = actor
        finding.escalate_at = None
        finding.save()
        findings.record(tx, finding, "acknowledged", actor, severity="info")
    return finding


def _why(value: Any, what: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValidationError(f"say {what} (reason)")
    if len(text) > 1000:
        raise ValidationError("reason is 1000 characters at most")
    return text


def at_current_step(tx: db.Where, finding: Finding, name: str) -> bool:
    """Whether the person ``name`` is among the people and teams the issue is with now."""
    key = (name or "").lower()
    for level, people in chain(tx, finding):
        if level != finding.level:
            continue
        for person in people:
            if person.kind == "person" and person.name.lower() == key:
                return True
            if key in {e.lower() for e in (*person.emails, *person.members)}:
                return True
    return False


def decline(
    tx: db.Where,
    settings: Settings,
    finding: Finding,
    *,
    actor: str,
    name: str,
    reason: Any,
) -> list[str]:
    """Someone it is with says it isn't theirs, and why: it goes on to the next step of its
    chain at once, which hears why. At the last step, it stays there. Returns whom it went
    to (none when it stayed)."""
    lock(tx, finding)
    if finding.status != "open":
        raise InvalidTransition(f"finding is {finding.status}: only open findings are declined")
    why = _why(reason, "why it isn't yours")
    here = at_current_step(tx, finding, name)
    findings.record(tx, finding, "declined", actor, severity="info", why=why, by=name)
    steps = chain(tx, finding)
    step = _next(steps, finding.level) if here else None
    if step is None:
        return []
    finding.acknowledged_at = None
    finding.acknowledged_by = None
    _give(tx, settings, finding, step, steps, ids.utcnow(), escalated=True)
    return list(finding.assignees or [])


def ask_exception(
    tx: db.Where, finding: Finding, *, actor: str, name: str, reason: Any, until: Any
) -> Finding:
    """Someone it reached asks for its risk to be accepted until a date, and why: an approver
    decides (accept, or decline_exception). Meanwhile it stays with them, acknowledged."""
    lock(tx, finding)
    if finding.status != "open":
        raise InvalidTransition(f"finding is {finding.status}: only open findings take this")
    why = _why(reason, "why its risk is acceptable")
    end = parse_until(until)
    now = ids.utcnow()
    finding.details = {
        **(finding.details or {}),
        ASKED: {"by": name, "reason": why, "until": ids.isoformat(end), "at": ids.isoformat(now)},
    }
    if finding.acknowledged_at is None:
        finding.acknowledged_at, finding.acknowledged_by = now, actor
        finding.escalate_at = None
    finding.save()
    findings.record(tx, finding, "exception_requested", actor, why=why, until=ids.isoformat(end))
    return finding


def decline_exception(tx: db.Where, finding: Finding, *, actor: str, reason: Any) -> Finding:
    """An approver turns down a request to accept its risk, saying why: it stays with
    whoever asked, to fix."""
    lock(tx, finding)
    asked = (finding.details or {}).get(ASKED)
    if not asked:
        raise InvalidTransition("nobody asked for its risk to be accepted")
    why = _why(reason, "why not")
    finding.details = {k: v for k, v in (finding.details or {}).items() if k != ASKED}
    finding.save()
    findings.record(tx, finding, "exception_declined", actor, why=why, asked_by=asked.get("by"))
    return finding


def parse_until(value: Any, now: datetime | None = None) -> datetime:
    """An accepted risk's end: an ISO 8601 date or time, or a number of days from now."""
    now = now or ids.utcnow()
    if isinstance(value, int) and not isinstance(value, bool):
        until = now + timedelta(days=value)
    else:
        try:
            until = datetime.fromisoformat(str(value))
        except ValueError:
            raise ValidationError(
                "until is a date (2026-12-31), a time (2026-12-31T17:00:00Z) or days from now"
            ) from None
        # Times without a zone, and plain dates, are UTC.
        until = until.replace(tzinfo=UTC) if until.tzinfo is None else until.astimezone(UTC)
    if until <= now:
        raise ValidationError("until must be in the future")
    if until > now + MAX_ACCEPT:
        raise ValidationError("a risk is accepted for a year at most: then someone decides again")
    return until


def accountable(tx: db.Where, agent: Agent, name: str | None) -> str | None:
    """How the person ``name`` (an email address or user name) is accountable for
    ``agent``, in words, or None: they own it, sponsor it, or are in its team (its own or
    its blueprint's; not the default team, which only gets what nobody else does)."""
    key = (name or "").strip().lower()
    if not key:
        return None
    d = Directory(tx)
    blueprint = agent.blueprint
    team = agent.team or (blueprint.team if blueprint else None)
    for names, as_person, as_team in (
        ([agent.owner], "own", "are in the team that owns"),
        ([str(s) for s in agent.sponsors or []], "sponsor", "are in a team that sponsors"),
        ([team], "", "are in the team of"),
    ):
        for found in (d.recipient(n) for n in names):
            if found is None:
                continue
            people = {p.lower() for p in (*found.emails, *found.members)}
            if found.kind == "person":
                people.add(found.name.lower())
            if key in people:
                return f"you {as_person if found.kind == 'person' else as_team} {agent.name}"
    return None


def _not_accountable(tx: db.Where, finding: Finding, by: str | None, does: str) -> None:
    """Refuse ``by``, the person answering an issue, what someone accountable for its agent
    mustn't do: someone else signs that off."""
    agent = _agent(finding)
    why = accountable(tx, agent, by) if agent is not None else None
    if why:
        raise Forbidden(
            f"{why[0].upper()}{why[1:]}: someone who isn't accountable for it {does} "
            "(another approver, an administrator or the security team)"
        )


def dismiss(
    tx: db.Where,
    finding: Finding,
    *,
    reason: Any,
    actor: str,
    until: datetime | None = None,
    by: str | None = None,
) -> Finding:
    """Dismiss an issue that is wrong (findings.dismiss). It then goes to nobody, as one whose
    risk was accepted: ``by``, the person dismissing it, mustn't be accountable for its agent
    either."""
    _not_accountable(tx, finding, by, "dismisses its issues")
    return findings.dismiss(tx, finding, reason=reason, actor=actor, until=until)


def accept(
    tx: db.Where,
    finding: Finding,
    *,
    reason: Any,
    until: Any,
    actor: str,
    by: str | None = None,
) -> Finding:
    """Accept the risk until a date, for a reason: the finding stops going to anyone until
    then, and opens again at that date if it still holds. ``by``, the person accepting it,
    mustn't be accountable for the agent it is about: someone else signs that off."""
    lock(tx, finding)
    if finding.status not in ("open", "accepted"):
        raise InvalidTransition(f"finding is {finding.status}: only open findings are accepted")
    _not_accountable(tx, finding, by, "accepts its risks")
    reason = str(reason or "").strip()
    if not reason:
        raise ValidationError("say why the risk is acceptable (reason)")
    if len(reason) > 2000:
        raise ValidationError("reason is 2000 characters at most")
    finding.accepted_until = parse_until(until)
    finding.accepted_reason = reason
    finding.status = "accepted"
    finding.escalate_at = None
    # Whoever asked for it has their answer.
    finding.details = {k: v for k, v in (finding.details or {}).items() if k != ASKED}
    finding.save()
    findings.record(
        tx,
        finding,
        "accepted",
        actor,
        severity="warning",
        until=ids.isoformat(finding.accepted_until),
        why=reason,
    )
    return finding


# ---------------------------------------------------------------- what people see


def for_person(tx: db.Where, name: str | None, *, status: str | None = None) -> list[Finding]:
    """The issues that reached this person (by any name they go by: their email address,
    user principal name or user name), or one of the teams they are in."""
    names = directory_people.aliases(tx, name)
    if not names:
        return []
    found = Finding.objects.filter(level__isnull=False).order_by("-last_seen")
    if status and status != "all":
        found = found.filter(status=status)
    directory = Directory(tx)
    return [f for f in found if names & involved(tx, f, directory)]


def may_act(tx: db.Where, finding: Finding, name: str | None) -> bool:
    """Whether the issue reached the person, by any name they go by (their email address,
    or the user principal name they sign in with)."""
    return bool(directory_people.aliases(tx, name) & involved(tx, finding))


def describe(tx: db.Where, finding: Finding) -> list[dict[str, Any]]:
    """Its chain, step by step: who is at each step, and how far the issue has gone."""
    reached = LEVELS.index(finding.level) if finding.level else -1
    return [
        {
            "level": level,
            "who": [p.describe() for p in people],
            "reached": LEVELS.index(level) <= reached,
            "current": level == finding.level,
        }
        for level, people in chain(tx, finding)
    ]


def history(tx: db.Where, finding: Finding, limit: int = 200) -> list[LedgerEntry]:
    """What happened to it, newest first, from the ledger."""
    rows = (
        ledger.chain()
        .filter(type__startswith="finding.", resource=finding.subject)
        .order_by("-seq")[: limit * 5]
    )
    return [e for e in rows if (e.details or {}).get("finding_id") == finding.id][:limit]


def notifications(tx: db.Where, finding: Finding) -> list[dict[str, Any]]:
    rows = Notification.objects.filter(finding_id=finding.id).order_by("created_at")
    return [
        {
            "round": n.round,
            "level": n.level,
            "channel": n.channel,
            "recipient": n.recipient,
            "status": n.status,
            "attempts": n.attempts,
            "last_error": n.last_error,
            "sent_at": ids.isoformat(n.sent_at),
            "next_attempt_at": ids.isoformat(n.next_attempt_at) if n.status == "pending" else None,
        }
        for n in rows
    ]
