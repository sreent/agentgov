"""What waits for someone's decision, in one place (docs/administration.md#approvals):
each kind only for those who may decide it.

* Calls agents made that policy held for a person: approvers and administrators, the
  security team from the hand-off's decide level, or the person they were sent to.
* Access packages asked for agents: approvers and administrators, but not whoever asked.
* Risks people asked to be accepted: approvers and administrators, and the security team
  from triage on.
* Agents and tool servers registered for review, tool definitions that changed since they
  were approved, and agents found on platforms that nobody has reviewed: administrators.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids
from agentgov.models import DISCOVERED, PENDING, Agent, Finding, ToolServer
from agentgov.registry import access_packages, approvals, findings, issues, platforms
from agentgov.secops import handoff

# Listed with each kind, at most; its count says how many there are.
SHOWN = 50
DRIFT = "toolserver.tool_drift"


def gather(session: Session, principal: Any) -> dict[str, Any]:
    """The kinds of decision waiting for ``principal``, with how many of each."""
    roles = principal.roles
    admin = principal.is_admin
    approver = admin or "approver" in roles
    secops = "secops" in roles
    kinds: list[dict[str, Any]] = []

    def kind(name: str, title: str, rows: list[Any], view: Callable[[Any], Any]) -> None:
        items = [view(r) for r in rows[:SHOWN]]
        kinds.append({"kind": name, "title": title, "count": len(rows), "items": items})

    deciding = secops and handoff.at_least(session, handoff.DECIDE)
    held = [
        r
        for r in approvals.list_requests(session, status=approvals.PENDING, limit=1000)
        if approvals.may_decide(r, roles, principal.subject, secops=deciding)
    ]
    kind("calls", "Calls held for a decision", held, approvals.to_dict)

    if approver:
        mine = {principal.actor, principal.name}
        asked = [
            r
            for r in access_packages.assignments(session, status=access_packages.REQUESTED)
            if r.requested_by not in mine
        ]
        kind(
            "access",
            "Access packages asked for agents",
            asked,
            lambda r: access_packages.assignment_dict(session, r),
        )

    if approver or (secops and handoff.at_least(session, handoff.TRIAGE)):
        # The key as text: SQLite's JSON values come quoted, and a missing key would read
        # as the text null rather than NULL.
        asking = Finding.details[issues.ASKED].as_string().is_not(None)
        risks = list(
            session.scalars(
                select(Finding)
                .where(Finding.status == "open", asking)
                .order_by(Finding.last_seen.desc())
            )
        )
        kind("risks", "Risks asked to be accepted", risks, lambda f: _risk(session, f))

    if admin:
        waiting = list(
            session.scalars(select(Agent).where(Agent.status == PENDING).order_by(Agent.created_at))
        )
        kind("agents", "Agents waiting for approval", waiting, _agent)
        servers = list(
            session.scalars(
                select(ToolServer).where(ToolServer.status == PENDING).order_by(ToolServer.name)
            )
        )
        kind("toolservers", "Tool servers waiting for approval", servers, _server)
        drifted = list(
            session.scalars(
                select(Finding)
                .where(Finding.status == "open", Finding.type == DRIFT)
                .order_by(Finding.first_seen)
            )
        )
        kind("definitions", "Tool definitions changed since they were approved", drifted, _drift)
        unreviewed = _unreviewed(session)
        kinds.append(
            {
                "kind": "platform_agents",
                "title": "Agents found on platforms, not reviewed yet",
                "count": sum(unreviewed.values()),
                "items": [{"platform": p, "count": n} for p, n in sorted(unreviewed.items())],
            }
        )
    return {"total": sum(k["count"] for k in kinds), "kinds": kinds}


def _risk(session: Session, f: Finding) -> dict[str, Any]:
    agent = session.get(Agent, f.agent_id) if f.agent_id else None
    return {
        **findings.to_dict(f),
        "agent_name": agent.name if agent is not None else None,
        "asked": (f.details or {}).get(issues.ASKED),
    }


def _agent(a: Agent) -> dict[str, Any]:
    return {
        "id": a.id,
        "name": a.name,
        "status": a.status,
        "owner": a.owner,
        "sponsors": a.sponsors or [],
        "blueprint": a.blueprint.name if a.blueprint is not None else None,
        "created_by": a.created_by,
        "created_at": ids.isoformat(a.created_at),
    }


def _server(ts: ToolServer) -> dict[str, Any]:
    return {
        "id": ts.id,
        "name": ts.name,
        "url": ts.url,
        "owner": ts.owner,
        "created_by": ts.created_by,
        "created_at": ids.isoformat(ts.created_at),
    }


def _drift(f: Finding) -> dict[str, Any]:
    server, _, tool = f.subject.partition("/")
    since = ids.isoformat(f.first_seen)
    return {"finding_id": f.id, "server": server, "tool": tool, "since": since}


def _unreviewed(session: Session) -> dict[str, int]:
    """Agents found on each platform with nobody's review yet (gone ones aren't)."""
    gone = platforms.gone_agents(session)
    counts: dict[str, int] = {}
    for agent_id, source in session.execute(
        select(Agent.id, Agent.source).where(
            Agent.status == DISCOVERED, Agent.source.like("platform:%")
        )
    ):
        if agent_id in gone:
            continue
        name = platforms.SOURCES.get(source.removeprefix("platform:"))
        if name:
            counts[name] = counts.get(name, 0) + 1
    return counts


def total(session: Session, principal: Any) -> int:
    """How many decisions wait for ``principal``."""
    return int(gather(session, principal)["total"])
