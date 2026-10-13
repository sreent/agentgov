"""Teams: people and chat channels that can own agents, and that issues escalate to.

An agent's owner can name a team; its blueprint (or the agent itself) names the team that
issues about it escalate to after its owner and sponsors, and the default team takes the
issues that have no team of their own (docs/issues.md). A team is reached by email, at its
addresses (or its members', without any), and in its Teams and Slack channels, which are
destinations of those kinds. Its members see its issues in AgentGov and acknowledge them.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.models import DELETED, Agent, Blueprint, Destination, Team
from agentgov.registry import scopes, validation
from agentgov.registry.destinations import CHAT
from agentgov.registry.errors import Conflict, NotFound, ValidationError
from agentgov.registry.versions import changes, edited, start_edit

FIELDS = ("description", "members", "emails", "destinations", "default")
# Good enough to catch typos; the mail server has the last word.
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_email(value: str) -> bool:
    return bool(_EMAIL.match(value))


def get(session: Session, ref: str) -> Team:
    team = session.scalar(select(Team).where((Team.name == ref) | (Team.id == ref)))
    if team is None:
        raise NotFound(f"team {ref!r} not found")
    return team


def find(session: Session, name: str | None) -> Team | None:
    """The team of this name, if there is one."""
    if not name:
        return None
    return session.scalar(select(Team).where(Team.name == name))


def default(session: Session) -> Team | None:
    return session.scalar(select(Team).where(Team.is_default.is_(True)))


def reference(session: Session, value: Any) -> str | None:
    """A blueprint's or an agent's team: the name of a team there is, or none."""
    if value in (None, ""):
        return None
    name = str(value)
    if find(session, name) is None:
        raise ValidationError(f"team {name!r} not found: add it first")
    return name


def _with(
    own: str | None, blueprints: str | None, names: set[str], fallback: str | None
) -> str | None:
    """The team an agent is with: the first of its own team and its blueprint's that is a
    team, else the default team (as its issues reach a team)."""
    for name in (own, blueprints):
        if name and name in names:
            return name
    return fallback


def team_of(session: Session, agent: Agent) -> str | None:
    """The team ``agent`` is with, as its issues reach a team: its own, else its
    blueprint's, else the default team."""
    blueprint = agent.blueprint
    fallback = default(session)
    names = set(session.scalars(select(Team.name)))
    return _with(
        agent.team,
        blueprint.team if blueprint else None,
        names,
        fallback.name if fallback else None,
    )


def agents_in(session: Session, names: Any) -> set[str]:
    """The agents, by ID, that are with the teams ``names`` (any case): see team_of."""
    wanted = {str(name).lower() for name in names if name}
    if not wanted:
        return set()
    fallback = default(session)
    existing = set(session.scalars(select(Team.name)))
    rows = session.execute(
        select(Agent.id, Agent.team, Blueprint.team).outerjoin(
            Blueprint, Agent.blueprint_id == Blueprint.id
        )
    )
    return {
        agent_id
        for agent_id, own, blueprints in rows
        if (_with(own, blueprints, existing, fallback.name if fallback else None) or "").lower()
        in wanted
    }


def list_all(session: Session) -> list[Team]:
    return list(session.scalars(select(Team).order_by(Team.name)))


def _members(value: Any) -> list[str]:
    """People, by email address (lower case, as people sign in with them) or user name."""
    names = [m.lower() if is_email(m) else m for m in validation.string_list(value, "members")]
    return list(dict.fromkeys(names))


def _emails(value: Any) -> list[str]:
    emails = [e.lower() for e in validation.string_list(value, "emails")]
    bad = [e for e in emails if not is_email(e)]
    if bad:
        raise ValidationError(f"emails must be email addresses (not {', '.join(bad)})")
    return list(dict.fromkeys(emails))


def _destinations(session: Session, value: Any) -> list[str]:
    names = list(dict.fromkeys(validation.string_list(value, "destinations")))
    for name in names:
        destination = session.scalar(select(Destination).where(Destination.name == name))
        if destination is None:
            raise ValidationError(f"destination {name!r} not found: add it first")
        if destination.kind not in CHAT:
            raise ValidationError(
                f"destination {name!r} is a {destination.kind} destination: a team's channels "
                "are Teams or Slack destinations"
            )
    return names


def _apply(session: Session, team: Team, data: dict[str, Any]) -> list[str]:
    changed = []
    for key in FIELDS:
        if key not in data:
            continue
        value = data[key]
        if key == "members":
            value = _members(value)
        elif key == "emails":
            value = _emails(value)
        elif key == "destinations":
            value = _destinations(session, value)
        elif key == "description":
            value = str(value or "")
        elif key == "default":
            if not isinstance(value, bool):
                raise ValidationError("default is true or false")
            if value and not team.is_default:
                # One default team: the one marked last.
                session.execute(
                    update(Team).where(Team.is_default.is_(True)).values(is_default=False)
                )
            if team.is_default != value:
                team.is_default = value
                changed.append(key)
            continue
        if getattr(team, key) != value:
            setattr(team, key, value)
            changed.append(key)
    return changed


def _known(data: dict[str, Any], also: tuple[str, ...]) -> None:
    unknown = sorted(set(data) - set(FIELDS) - set(also))
    if unknown:
        raise ValidationError(
            f"unknown field(s) {', '.join(unknown)}; a team takes {', '.join((*also, *FIELDS))}"
        )


def create(session: Session, data: dict[str, Any], *, actor: str) -> Team:
    _known(data, ("name",))
    name = validation.slug(data.get("name"), "name")
    if find(session, name):
        raise Conflict(f"team {name!r} already exists")
    team = Team(
        id=ids.new_id(ids.TEAM),
        name=name,
        description="",
        members=[],
        emails=[],
        destinations=[],
        is_default=False,
    )
    _apply(session, team, data)
    session.add(team)
    session.flush()
    ledger.append(
        session,
        type="team.created",
        actor=actor,
        resource=f"team/{name}",
        details=_details(team),
    )
    return team


def update_team(
    session: Session,
    team: Team,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
) -> list[str]:
    start_edit(session, team, version, f"team {team.name}")
    _known(data, ("name",))
    if "name" in data and data["name"] != team.name:
        raise ValidationError("a team's name can't change: agents and blueprints name it")
    changed = _apply(session, team, data)
    if changed:
        edited(team)
        ledger.append(
            session,
            type="team.updated",
            actor=actor,
            resource=f"team/{team.name}",
            details={**{k: _details(team)[k] for k in changed}, "changes": changes(team)},
        )
    return changed


def users(session: Session, name: str, *, reached: set[str] | None = None) -> list[str]:
    """The blueprints and agents that name a team (as their team, owner or sponsor), and
    the controls' exceptions and management rules. ``reached``: the agents (by ID) of a role
    for some teams only, which reads only those, and no exceptions or rules."""
    found = scopes.naming(session, "teams", name) if reached is None else []
    found += [
        f"blueprint {b}"
        for b in session.scalars(select(Blueprint.name).where(Blueprint.team == name))
    ]
    rows = session.execute(
        select(Agent.id, Agent.name, Agent.team, Agent.owner, Agent.sponsors).where(
            Agent.status != DELETED
        )
    )
    found += [
        f"agent {agent}"
        for agent_id, agent, team, owner, sponsors in rows
        if (name in (team, owner) or name in (sponsors or []))
        and (reached is None or agent_id in reached)
    ]
    return sorted(found)


def delete(session: Session, team: Team, *, actor: str) -> None:
    named_by = users(session, team.name)
    if named_by:
        more = f" and {len(named_by) - 5} more" if len(named_by) > 5 else ""
        raise Conflict(
            f"{', '.join(named_by[:5])}{more} name team {team.name!r}: name another team or "
            "person there first"
        )
    ledger.append(
        session,
        type="team.deleted",
        actor=actor,
        resource=f"team/{team.name}",
        severity="warning",
    )
    session.delete(team)


def _details(team: Team) -> dict[str, Any]:
    return {
        "description": team.description or "",
        "members": list(team.members or []),
        "emails": list(team.emails or []),
        "destinations": list(team.destinations or []),
        "default": team.is_default,
    }


def to_dict(team: Team) -> dict[str, Any]:
    return {
        "id": team.id,
        "name": team.name,
        "version": team.version,
        **_details(team),
        "created_at": ids.isoformat(team.created_at),
        "updated_at": ids.isoformat(team.updated_at),
    }
