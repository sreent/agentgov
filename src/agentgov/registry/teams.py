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

from django.db.models import Q

from agentgov import db, ids, ledger
from agentgov.db.models import DELETED, Agent, Blueprint, Destination, Team
from agentgov.registry import scopes, validation
from agentgov.registry.destinations import CHAT
from agentgov.registry.errors import Conflict, NotFound, ValidationError
from agentgov.registry.versions import changes, edited, start_edit

FIELDS = ("description", "members", "emails", "destinations", "default")
# Good enough to catch typos; the mail server has the last word.
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_email(value: str) -> bool:
    return bool(_EMAIL.match(value))


def get(tx: db.Transaction, ref: str) -> Team:
    team = Team.objects.filter(Q(name=ref) | Q(id=ref)).first()
    if team is None:
        raise NotFound(f"team {ref!r} not found")
    return team


def find(tx: db.Transaction, name: str | None) -> Team | None:
    """The team of this name, if there is one."""
    if not name:
        return None
    return Team.objects.filter(name=name).first()


def default(tx: db.Transaction) -> Team | None:
    return Team.objects.filter(is_default=True).first()


def all_names(tx: db.Transaction) -> set[str]:
    """The teams' names."""
    return set(Team.objects.values_list("name", flat=True))


def reference(tx: db.Transaction, value: Any) -> str | None:
    """A blueprint's or an agent's team: the name of a team there is, or none."""
    if value in (None, ""):
        return None
    name = str(value)
    if find(tx, name) is None:
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


def team_of(tx: db.Transaction, agent: Agent) -> str | None:
    """The team ``agent`` is with, as its issues reach a team: its own, else its
    blueprint's, else the default team."""
    blueprint = agent.blueprint
    fallback = default(tx)
    return _with(
        agent.team,
        blueprint.team if blueprint else None,
        all_names(tx),
        fallback.name if fallback else None,
    )


def agents_in(tx: db.Transaction, names: Any) -> set[str]:
    """The agents, by ID, that are with the teams ``names`` (any case): see team_of."""
    wanted = {str(name).lower() for name in names if name}
    if not wanted:
        return set()
    fallback = default(tx)
    existing = all_names(tx)
    rows = Agent.objects.values_list("id", "team", "blueprint__team")
    return {
        agent_id
        for agent_id, own, blueprints in rows
        if (_with(own, blueprints, existing, fallback.name if fallback else None) or "").lower()
        in wanted
    }


def list_all(tx: db.Transaction) -> list[Team]:
    return list(Team.objects.order_by("name"))


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


def _destinations(tx: db.Transaction, value: Any) -> list[str]:
    names = list(dict.fromkeys(validation.string_list(value, "destinations")))
    for name in names:
        destination = Destination.objects.filter(name=name).first()
        if destination is None:
            raise ValidationError(f"destination {name!r} not found: add it first")
        if destination.kind not in CHAT:
            raise ValidationError(
                f"destination {name!r} is a {destination.kind} destination: a team's channels "
                "are Teams or Slack destinations"
            )
    return names


def _apply(tx: db.Transaction, team: Team, data: dict[str, Any]) -> list[str]:
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
            value = _destinations(tx, value)
        elif key == "description":
            value = str(value or "")
        elif key == "default":
            if not isinstance(value, bool):
                raise ValidationError("default is true or false")
            if value and not team.is_default:
                # One default team: the one marked last.
                Team.objects.filter(is_default=True).update(
                    is_default=False, updated_at=ids.utcnow()
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


def create(tx: db.Transaction, data: dict[str, Any], *, actor: str) -> Team:
    _known(data, ("name",))
    name = validation.slug(data.get("name"), "name")
    if find(tx, name):
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
    _apply(tx, team, data)
    team.save(force_insert=True)
    ledger.append(
        tx,
        type="team.created",
        actor=actor,
        resource=f"team/{name}",
        details=_details(team),
    )
    return team


def update_team(
    tx: db.Transaction,
    team: Team,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
) -> list[str]:
    start_edit(tx, team, version, f"team {team.name}")
    _known(data, ("name",))
    if "name" in data and data["name"] != team.name:
        raise ValidationError("a team's name can't change: agents and blueprints name it")
    changed = _apply(tx, team, data)
    if changed:
        edited(team)
        team.save()
        ledger.append(
            tx,
            type="team.updated",
            actor=actor,
            resource=f"team/{team.name}",
            details={**{k: _details(team)[k] for k in changed}, "changes": changes(team)},
        )
    return changed


def users(tx: db.Transaction, name: str, *, reached: set[str] | None = None) -> list[str]:
    """The blueprints and agents that name a team (as their team, owner or sponsor), and
    the controls' exceptions and management rules. ``reached``: the agents (by ID) of a role
    for some teams only, which reads only those, and no exceptions or rules."""
    found = scopes.naming(tx, "teams", name) if reached is None else []
    found += [
        f"blueprint {b}" for b in Blueprint.objects.filter(team=name).values_list("name", flat=True)
    ]
    rows = Agent.objects.exclude(status=DELETED).values_list(
        "id", "name", "team", "owner", "sponsors"
    )
    found += [
        f"agent {agent}"
        for agent_id, agent, team, owner, sponsors in rows
        if (name in (team, owner) or name in (sponsors or []))
        and (reached is None or agent_id in reached)
    ]
    return sorted(found)


def delete(tx: db.Transaction, team: Team, *, actor: str) -> None:
    named_by = users(tx, team.name)
    if named_by:
        more = f" and {len(named_by) - 5} more" if len(named_by) > 5 else ""
        raise Conflict(
            f"{', '.join(named_by[:5])}{more} name team {team.name!r}: name another team or "
            "person there first"
        )
    ledger.append(
        tx,
        type="team.deleted",
        actor=actor,
        resource=f"team/{team.name}",
        severity="warning",
    )
    team.delete()


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
