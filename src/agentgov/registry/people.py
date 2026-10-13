"""Who made each agent on another platform, and who owns it there
(docs/platforms.md#who-made-each-agent).

Copilot Studio names an agent's owner and its creator by their Microsoft Entra object IDs,
and Databricks its creator by email address. AgentGov keeps the people behind those IDs as
the directory says: their name, email address, and whether their account is enabled. It
reads them with Microsoft Graph, through its app registration (User.Read.All; with
User.ReadBasic.All, not whether accounts are enabled) or as an administrator signed in with
Microsoft who syncs Copilot Studio, or from a list of users uploaded from the directory
(the Microsoft Entra admin center's **Download users**, which any user can do). With none
of them, a maker is shown by their ID, and whoever adopts the agent names its owner.

The people looked up are read again after a week: one the directory had, and has no
more, has left (``gone_at``).
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.models import DELETED, DISCOVERED, Agent, Person, PlatformAgent
from agentgov.registry import agents as agents_svc
from agentgov.registry import platforms
from agentgov.registry.errors import NotFound, RegistryError, ValidationError

GUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
OWNER, CREATOR = "owner", "creator"
GRAPH, UPLOAD = "graph", "upload"
# People are read again after this long, to see who has left.
RECHECK = timedelta(days=7)
# Looked up in one run at most; the rest wait for the next.
MAX_LOOKUP = 2000
# Users in one uploaded list, at most.
MAX_LIST = 200_000
# Agents adopted at once, at most.
MAX_ADOPT = 500
# Lines some exports put before the header: a format version, PowerShell's type name.
PREAMBLE = ("version:", "#type", "sep=")
# The columns of a list of users, by their name without case, spaces or punctuation:
# the Entra admin center's download (objectId, userPrincipalName, displayName, mail,
# accountEnabled), Get-MgUser | Export-Csv (Id, ...), and Graph's own JSON (id, ...).
COLUMNS = {
    "id": ("objectid", "id"),
    "mail": ("mail", "email", "emailaddress"),
    "upn": ("userprincipalname", "upn"),
    "name": ("displayname", "name"),
    "enabled": ("accountenabled", "enabled"),
    # Older downloads said the opposite: whether sign-in is blocked.
    "blocked": ("blockcredential", "blocksignin"),
}
TRUE, FALSE = {"true", "yes", "1"}, {"false", "no", "0"}


def named(record: PlatformAgent) -> list[dict[str, str]]:
    """Whom a platform names for one of its agents: its owner there and its creator, by
    Entra object ID (Copilot Studio) or email address (``maker``, from a connector)."""
    data = record.data or {}
    out: list[dict[str, str]] = []
    for role, key in ((OWNER, "owner_id"), (CREATOR, "created_by")):
        value = str(data.get(key) or "").strip().lower()
        if GUID.match(value):
            out.append({"role": role, "entra_id": value})
    maker = str(data.get("maker") or "").strip()
    if "@" in maker:
        out.append({"role": CREATOR, "email": maker.lower()})
    return out


def _records(session: Session) -> list[PlatformAgent]:
    """The platform records of agents in the registry (not deleted)."""
    return list(
        session.scalars(
            select(PlatformAgent)
            .join(Agent, Agent.id == PlatformAgent.agent_id)
            .where(Agent.status != DELETED)
        )
    )


def wanted(session: Session, now: datetime | None = None, *, limit: int = MAX_LOOKUP) -> list[str]:
    """The Entra object IDs platforms name that AgentGov hasn't looked up, then those it
    looked up longest ago, over a week ago."""
    now = now or ids.utcnow()
    named_ids = {n["entra_id"] for r in _records(session) for n in named(r) if "entra_id" in n}
    known = {p.id: p for p in session.scalars(select(Person))}
    unknown = sorted(i for i in named_ids if i not in known)
    stale = sorted(
        (known[i] for i in named_ids if i in known and known[i].checked_at < now - RECHECK),
        key=lambda p: p.checked_at,
    )
    return (unknown + [p.id for p in stale])[:limit]


def record_lookup(
    session: Session,
    found: list[dict[str, Any]],
    missing: list[str],
    *,
    actor: str | None = None,
) -> dict[str, int]:
    """Keep what the directory said about the people looked up: those it has, and those it
    hasn't (a user it had before has left)."""
    now = ids.utcnow()
    counts = {"found": 0, "not_found": 0, "left": 0}
    for user in found:
        oid = str(user.get("id") or "").lower()
        if not GUID.match(oid):
            continue
        person = session.get(Person, oid) or Person(id=oid, source=GRAPH)
        person.name = user.get("displayName") or person.name
        person.email = user.get("mail") or user.get("userPrincipalName") or person.email
        if "accountEnabled" in user:
            person.enabled = user["accountEnabled"]
        person.found, person.gone_at, person.source, person.checked_at = True, None, GRAPH, now
        session.add(person)
        counts["found"] += 1
    for oid in missing:
        person = session.get(Person, oid.lower())
        if person is None:
            person = Person(id=oid.lower(), found=False, source=GRAPH)
            counts["not_found"] += 1
        elif person.found:
            # The directory had them, and has no more: they left.
            person.found, person.gone_at = False, now
            counts["left"] += 1
            ledger.append(
                session,
                type="person.left",
                actor=actor or "system:entra-users",
                severity="warning",
                resource=f"person/{person.id}",
                details={"name": person.name, "email": person.email},
            )
        person.source, person.checked_at = GRAPH, now
        session.add(person)
    return counts


def _rows(payload: Any) -> list[dict[str, Any]]:
    """The users in an uploaded list: CSV text, or JSON (a list, or Graph's {"value": [...]})."""
    if isinstance(payload, dict):
        payload = payload.get("value", payload.get("users"))
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if not isinstance(payload, str):
        raise ValidationError(
            "send the list of users as CSV (the Entra admin center's Download users) or JSON"
        )
    lines = payload.lstrip("﻿").splitlines()
    while lines and lines[0].strip().lower().startswith(PREAMBLE):
        lines.pop(0)
    return list(csv.DictReader(io.StringIO("\n".join(lines))))


def _column(row: dict[str, Any], key: str) -> Any:
    names = COLUMNS[key]
    for column, value in row.items():
        if re.sub(r"[^a-z]", "", str(column).lower()) in names and value not in (None, ""):
            return value
    return None


def import_list(session: Session, payload: Any, *, actor: str) -> dict[str, int]:
    """Keep the people in a list of users uploaded from the directory. A user the list
    leaves out isn't taken to have left: it may be filtered."""
    rows = _rows(payload)
    if len(rows) > MAX_LIST:
        raise ValidationError(f"a list of {MAX_LIST} users at most")
    now = ids.utcnow()
    counts = {"people": 0, "skipped": 0}
    for row in rows:
        oid = str(_column(row, "id") or "").strip().lower()
        if not GUID.match(oid):
            counts["skipped"] += 1  # no object ID: nothing to match a platform's to
            continue
        person = session.get(Person, oid) or Person(id=oid, source=UPLOAD)
        person.name = _column(row, "name") or person.name
        person.email = _column(row, "mail") or _column(row, "upn") or person.email
        enabled = str(_column(row, "enabled") or "").strip().lower()
        blocked = str(_column(row, "blocked") or "").strip().lower()
        if enabled in TRUE | FALSE:
            person.enabled = enabled in TRUE
        elif blocked in TRUE | FALSE:
            person.enabled = blocked in FALSE
        person.found, person.gone_at, person.source, person.checked_at = True, None, UPLOAD, now
        session.add(person)
        counts["people"] += 1
    if not counts["people"]:
        raise ValidationError(
            "no user in the list has an object ID: send the Entra admin center's Download "
            "users file (objectId, userPrincipalName, displayName, mail), or one with id and "
            "mail columns"
        )
    ledger.append(
        session,
        type="people.imported",
        actor=actor,
        resource="platform/entra-users",
        details=counts,
    )
    return counts


def _describe(entry: dict[str, str], person: Person | None) -> dict[str, Any]:
    out: dict[str, Any] = dict(entry)
    if "email" in entry:  # a platform that names people by email address
        out.update(name=None, known=True, looked_up=False, enabled=None, left=False, left_at=None)
        return out
    out.update(
        name=person.name if person else None,
        email=person.email if person else None,
        # Whether the directory was asked about them; found: whether it has them.
        known=person is not None and person.found,
        looked_up=person is not None,
        enabled=person.enabled if person else None,
        left=bool(person and person.gone_at),
        left_at=ids.isoformat(person.gone_at) if person and person.gone_at else None,
    )
    return out


def for_records(session: Session, records: list[PlatformAgent]) -> dict[str, list[dict[str, Any]]]:
    """For each agent, the people its platforms name, with what AgentGov knows about each:
    its owner on the platform first. One entry per person, with their roles."""
    entries: dict[str, dict[tuple[str, str], dict[str, Any]]] = {}
    for record in records:
        for entry in named(record):
            key = "entra_id" if "entra_id" in entry else "email"
            who = (key, entry[key])
            people = entries.setdefault(record.agent_id, {})
            if who in people:
                if entry["role"] not in people[who]["roles"]:
                    people[who]["roles"].append(entry["role"])
                continue
            people[who] = {
                **{k: v for k, v in entry.items() if k != "role"},
                "roles": [entry["role"]],
                "source": record.source,
            }
    wanted_ids = {
        e["entra_id"] for people in entries.values() for e in people.values() if "entra_id" in e
    }
    known = (
        {p.id: p for p in session.scalars(select(Person).where(Person.id.in_(wanted_ids)))}
        if wanted_ids
        else {}
    )
    out: dict[str, list[dict[str, Any]]] = {}
    for agent_id, people in entries.items():
        described = [_describe(e, known.get(e.get("entra_id", ""))) for e in people.values()]
        described.sort(key=lambda e: OWNER not in e["roles"])
        out[agent_id] = described
    return out


def for_agent(session: Session, agent_id: str) -> list[dict[str, Any]]:
    """The people the agent's platforms name, with what AgentGov knows about each."""
    records = list(session.scalars(select(PlatformAgent).where(PlatformAgent.agent_id == agent_id)))
    return for_records(session, records).get(agent_id, [])


def _usable(person: dict[str, Any]) -> bool:
    """Whether a maker can own the agent: AgentGov knows their email address, and they
    haven't left (nor had their account disabled)."""
    return bool(
        person.get("email")
        and person.get("known")
        and not person.get("left")
        and person.get("enabled") is not False
    )


def suggested(makers: list[dict[str, Any]]) -> str | None:
    """Whom to make an agent's owner and sponsor when adopting it: its owner on the
    platform, else its creator, when they can own it."""
    person = next((m for m in makers if _usable(m)), None)
    return str(person["email"]).lower() if person else None


def shown(makers: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The one to show where there is room for one: whom adopting suggests, else the
    platform's owner."""
    return next((m for m in makers if _usable(m)), makers[0] if makers else None)


def summary(session: Session) -> dict[str, int]:
    """How many people platforms name, how many AgentGov knows, and how many have left."""
    named_ids = {n["entra_id"] for r in _records(session) for n in named(r) if "entra_id" in n}
    known = {p.id: p for p in session.scalars(select(Person))}
    return {
        "named": len(named_ids),
        "known": sum(1 for i in named_ids if i in known and known[i].found),
        "unknown": sum(1 for i in named_ids if i not in known),
        "left": sum(1 for i in named_ids if i in known and known[i].gone_at is not None),
        "disabled": sum(1 for i in named_ids if i in known and known[i].enabled is False),
    }


def adopt(
    session: Session,
    settings: Settings,
    refs: list[str],
    *,
    owner: str | None,
    sponsors: list[str] | None,
    makers: bool,
    actor: str,
    reason: str | None = None,
) -> dict[str, Any]:
    """Adopt agents found on platforms at once, each pending review: with ``makers``, its
    maker on its platform as owner and sponsor, where AgentGov knows them; ``owner`` and
    ``sponsors`` for the others (all of them, without ``makers``). An agent that can't be
    adopted (not waiting to be, or with nobody to own it) is left as it is, and the answer
    says why."""
    if not refs or len(refs) > MAX_ADOPT:
        raise ValidationError(f"name the agents to adopt: one at least, {MAX_ADOPT} at most")
    if not owner and not makers:
        raise ValidationError("give them an owner, or their makers (makers: true)")
    adopted: list[dict[str, Any]] = []
    left: list[dict[str, str]] = []
    for ref in dict.fromkeys(refs):
        try:
            agent = agents_svc.get(session, ref)
        except NotFound:
            left.append({"agent": ref, "why": "there is no such agent"})
            continue
        if agent.status != DISCOVERED:
            left.append(
                {
                    "agent": agent.name,
                    "why": f"it isn't waiting to be adopted: it is {agent.status}",
                }
            )
            continue
        maker = suggested(for_agent(session, agent.id)) if makers else None
        its_owner = maker or owner
        its_sponsors = [maker] if maker else (sponsors or [])
        if not its_owner:
            left.append(
                {"agent": agent.name, "why": "AgentGov doesn't know who made it: give it an owner"}
            )
            continue
        try:
            with session.begin_nested():
                agents_svc.update(
                    session, agent, {"owner": its_owner, "sponsors": its_sponsors}, actor=actor
                )
                agents_svc.transition(session, settings, agent, "adopt", actor=actor, reason=reason)
                agents_svc.refresh_risk(session, settings, agent)
        except RegistryError as exc:
            left.append({"agent": agent.name, "why": str(exc)})
            continue
        adopted.append(
            {"agent": agent.name, "id": agent.id, "owner": its_owner, "sponsors": its_sponsors}
        )
    if adopted:
        platforms.review_summary(session)
    return {"adopted": adopted, "left": left}
