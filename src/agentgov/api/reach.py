"""What a person or an API key reaches: a role held for every team reaches every agent; one
held for some teams only (approver@sales) reaches those teams' agents, and what hangs off
them: their issues, approval requests, ledger entries and model usage
(docs/administration.md#roles-for-one-team).

Endpoints about agents take roles held for one team through these: their lists hold only
the agents in reach, an agent out of reach is not found, and what they change stays in
reach, governed no less (Hold). Every other endpoint checks roles held for every team
(agentgov.api.auth.require), which roles for one team never are: for those endpoints, they
reach nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from agentgov.api.auth import READ_ROLES, Principal, authenticate
from agentgov.identity import sso
from agentgov.models import Agent
from agentgov.registry import agents as agents_svc
from agentgov.registry import features, model_providers
from agentgov.registry import rules as rules_svc
from agentgov.registry import teams as teams_svc
from agentgov.registry.errors import Forbidden, NotFound
from agentgov.registry.validation import covers


def teams(principal: Principal, *roles: str) -> frozenset[str] | None:
    """The teams whose agents ``principal`` may act on with one of ``roles``: None for
    every team; else those it holds one of them for (an admin role counts as each), which
    may be none."""
    wanted = set(roles) | {"admin"}
    if principal.roles & wanted:
        return None
    return frozenset(
        team for role, names in principal.teams.items() if role in wanted for team in names
    )


def agent_ids(session: Session, principal: Principal, *roles: str) -> set[str] | None:
    """The agents, by ID, that ``principal`` reaches with one of ``roles``: None for all."""
    names = teams(principal, *roles)
    return None if names is None else teams_svc.agents_in(session, names)


def reaches(session: Session, principal: Principal, agent: Agent, *roles: str) -> bool:
    """Whether ``principal`` reaches ``agent`` with one of ``roles``."""
    names = teams(principal, *roles)
    if names is None:
        return True
    team = teams_svc.team_of(session, agent)
    return team is not None and team.lower() in {name.lower() for name in names}


def roles_at(session: Session, principal: Principal, agent: Agent | None) -> frozenset[str]:
    """``principal``'s roles where ``agent`` is: those held for every team, and those held
    for the agent's team, by their own names (approver), so that the checks that name roles
    take them there."""
    held = principal.teams
    if agent is None or not held:
        return principal.roles
    team = (teams_svc.team_of(session, agent) or "").lower()
    here = {role for role, names in held.items() if team in {n.lower() for n in names}}
    return principal.roles | here


def here(session: Session, principal: Principal, agent: Agent | None) -> Principal:
    """``principal`` as it is where ``agent`` is (see roles_at), for the checks that look at
    a principal's roles."""
    return replace(principal, roles=roles_at(session, principal, agent))


def by_agent(session: Session, principal: Principal) -> Callable[[str | None], frozenset[str]]:
    """``principal``'s roles where each agent is, by its ID (see roles_at), worked out once
    for a list."""
    held = {role: teams_svc.agents_in(session, names) for role, names in principal.teams.items()}

    def at(agent_id: str | None) -> frozenset[str]:
        if not agent_id or not held:
            return principal.roles
        return principal.roles | {role for role, ids in held.items() if agent_id in ids}

    return at


def agent(session: Session, principal: Principal, ref: str, *roles: str) -> Agent:
    """The agent ``ref`` names, if ``principal`` reaches it with one of ``roles`` (any role
    that reads, by default); else not found."""
    found = agents_svc.get(session, ref)
    check(session, principal, found, *(roles or READ_ROLES), ref=ref)
    return found


def check(
    session: Session, principal: Principal, agent: Agent, *roles: str, ref: str | None = None
) -> None:
    """Not found, for an agent ``principal`` doesn't reach with one of ``roles``: in the words
    used for one there isn't (registry.agents.get)."""
    if not reaches(session, principal, agent, *roles):
        raise NotFound(f"agent {ref or agent.id!r} not found")


def keep(session: Session, principal: Principal, agent: Agent, *roles: str) -> None:
    """Refuse a change that takes ``agent`` out of the teams ``principal`` reaches."""
    if not reaches(session, principal, agent, *roles):
        names = ", ".join(sorted(teams(principal, *roles) or ()))
        raise Forbidden(f"{agent.name} would no longer be with your teams ({names})")


@dataclass(frozen=True)
class Governed:
    """What governs an agent, as far as a role for some teams only mustn't loosen it: each
    control's mode for it, the management rules whose scope it is in, and what it may call
    (its own grants and its blueprint's): tools, models and agents."""

    modes: dict[str, str]
    rules: frozenset[str]
    tools: tuple[tuple[str, str], ...]
    models: tuple[tuple[str, str], ...]
    agents: tuple[str, ...]


class Hold:
    """Refuses a role for some teams only a change to an agent that loosens what governs it: a
    control's mode for it made weaker (an exception's scope it moved into), a management
    rule's scope it left, or a grant it gained. Those are for administrators for every team,
    and grants for access packages too (docs/administration.md#roles-for-one-team). Call
    ``before`` ahead of each change, ``check`` after it."""

    def __init__(self, session: Session, principal: Principal) -> None:
        self.free = principal.is_admin
        self.was: dict[str, Governed] = {}
        if not self.free:
            self.current = features.modes(session)
            self.exceptions = features.all_scopes(session)
            self.rules = rules_svc.list_all(session)

    def _governed(self, agent: Agent) -> Governed:
        differ = features.exceptions_for(agent, self.current, self.exceptions)
        return Governed(
            modes={
                key: differ.get(key, {}).get("mode", self.current[key])
                for key in features.SCOPABLE
                if key in self.current
            },
            rules=frozenset(r.name for r in self.rules if rules_svc.in_scope(r, agent)),
            tools=tuple(
                (g["server"], tool)
                for g in agents_svc.effective_grants(agent)
                for tool in g["tools"]
            ),
            models=tuple(
                (g["provider"], model)
                for g in model_providers.effective_model_access(agent)
                for model in g["models"]
            ),
            agents=tuple(agents_svc.effective_agent_access(agent)),
        )

    def before(self, agent: Agent) -> None:
        if not self.free:
            self.was[agent.id] = self._governed(agent)

    def check(self, agent: Agent) -> None:
        was = self.was.pop(agent.id, None)
        if was is None:
            return
        now = self._governed(agent)
        why = [
            f"its {key} mode would be {now.modes[key]}, not {mode}"
            for key, mode in was.modes.items()
            if features.BY_KEY[key].modes.index(now.modes[key])
            < features.BY_KEY[key].modes.index(mode)
        ]
        why += [
            f"management rule {name} would no longer look at it"
            for name in sorted(was.rules - now.rules)
        ]
        if why:
            raise Forbidden(
                f"{agent.name}: {'; '.join(why)}: an administrator for every team loosens what "
                "governs an agent"
            )
        gained = [
            f"tool {server}/{tool}"
            for server, tool in now.tools
            if not any(covers(s, server) and covers(t, tool) for s, t in was.tools)
        ]
        gained += [
            f"model {provider}/{model}"
            for provider, model in now.models
            if not any(p == provider and covers(m, model) for p, m in was.models)
        ]
        gained += [
            f"calls to agents {pattern}"
            for pattern in now.agents
            if not any(covers(p, pattern) for p in was.agents)
        ]
        if gained:
            raise Forbidden(
                f"{agent.name} would gain {', '.join(gained)}: ask for an access package, or an "
                "administrator for every team grants it"
            )


def require(*roles: str) -> Callable[[Request], Principal]:
    """Whoever holds one of ``roles``, for every team or for some (an admin role counts as
    each): the endpoint then limits what it does to the agents in reach."""
    allowed = set(roles) | {"admin"}

    def dependency(request: Request) -> Principal:
        principal = authenticate(request)
        if principal is None:
            raise HTTPException(
                status_code=401,
                detail="missing or invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if principal.roles & allowed or allowed & set(principal.teams):
            return principal
        raise HTTPException(status_code=403, detail=f"role {principal.role!r} may not do this")

    return dependency


read = require(*READ_ROLES)


def mark(
    rows: list[dict[str, Any]], session: Session, principal: Principal, key: str = "id"
) -> list[dict[str, Any]]:
    """For someone with roles for some teams only: on each row about an agent (its ID at
    ``key``), ``your_roles``, the roles they hold where that agent is, which the admin UI
    shows its actions by. The rows."""
    if not principal.teams:
        return rows
    at = by_agent(session, principal)
    for row in rows:
        row["your_roles"] = sorted(at(row.get(key)) & set(sso.SSO_ROLES))
    return rows
