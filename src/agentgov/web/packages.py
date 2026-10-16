"""Access packages: grants agents hold for a while once approved (docs/access-packages.md)."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest
from ninja import Body

from agentgov.api import reach
from agentgov.api.auth import READ_ROLES, Principal
from agentgov.api.versions import if_match
from agentgov.db.models import AccessAssignment
from agentgov.models import Agent
from agentgov.registry import access_packages, agents
from agentgov.registry.errors import NotFound, ValidationError
from agentgov.secops import handoff
from agentgov.web.api import HTTPException, Router
from agentgov.web.auth import guard, require, runtime, signed_in

router = Router(tags=["access packages"])
admin = require("admin")


def _responsible(session: Any, principal: Principal, agent: Agent) -> bool:
    """The agent's owner or a sponsor (or in a team named as either), signed in as
    themselves (Principal.person)."""
    person = principal.person
    return person is not None and person.lower() in access_packages.responsible(session, agent)


def _in_reach(
    session: Any, principal: Principal, agent: Agent, missing: str | None = None
) -> Principal:
    """Who ``principal`` is where the agent is (reach.here), if it is in their reach: they read
    AgentGov there, ask for its access packages, or are its owner or a sponsor. For anyone
    else it isn't there (``missing`` says what isn't)."""
    here = reach.here(session, principal, agent)
    known = set(READ_ROLES) | access_packages.REQUESTERS
    if not here.roles & known and not _responsible(session, principal, agent):
        raise NotFound(missing or f"agent {agent.id!r} not found")
    return here


def _may_read(
    session: Any, principal: Principal, agent: Agent, missing: str | None = None
) -> Principal:
    """Who reads what the agent holds: everyone who reads AgentGov where it is, and its
    owner and sponsors. Who ``principal`` is there (reach.here)."""
    here = _in_reach(session, principal, agent, missing)
    if not here.roles & set(READ_ROLES) and not _responsible(session, principal, agent):
        raise HTTPException(403, f"role {principal.role!r} may not do this")
    return here


# --------------------------------------------------------------------- packages


@router.get("/v1/access-packages", auth=signed_in)
def list_packages(request: HttpRequest) -> list[dict[str, Any]]:
    """Everyone signed in: people ask for packages for the agents they own or sponsor."""
    with runtime(request).db.session() as s:
        return [access_packages.to_dict(s, p) for p in access_packages.list_all(s)]


@router.post("/v1/access-packages", status_code=201, auth=admin)
def create_package(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    with runtime(request).db.session() as s:
        package = access_packages.create(s, body, actor=request.auth.actor)
        return access_packages.to_dict(s, package)


@router.get("/v1/access-packages/{ref}", auth=signed_in)
def get_package(request: HttpRequest, ref: str) -> dict[str, Any]:
    with runtime(request).db.session() as s:
        return access_packages.to_dict(s, access_packages.get(s, ref))


@router.patch("/v1/access-packages/{ref}", auth=admin)
def update_package(
    request: HttpRequest, ref: str, body: dict[str, Any] = Body(...)
) -> dict[str, Any]:
    """Change a package: every agent that holds it gets the change."""
    with runtime(request).db.session() as s:
        package = access_packages.get(s, ref)
        access_packages.update(
            s, package, body, actor=request.auth.actor, version=if_match(request)
        )
        return access_packages.to_dict(s, package)


@router.delete("/v1/access-packages/{ref}", auth=admin)
def delete_package(request: HttpRequest, ref: str) -> dict[str, str]:
    with runtime(request).db.session() as s:
        access_packages.delete(s, access_packages.get(s, ref), actor=request.auth.actor)
        return {"deleted": ref}


# ------------------------------------------------------------------ assignments


@router.get("/v1/access-assignments", auth=guard(reach.read))
def list_assignments(
    request: HttpRequest,
    status: str | None = None,
    agent: str | None = None,
    package: str | None = None,
) -> list[dict[str, Any]]:
    """What agents hold and asked for: for someone with roles for some teams only, their
    agents'."""
    principal = request.auth
    with runtime(request).db.session() as s:
        rows = access_packages.assignments(
            s,
            status=status,
            agent_id=reach.agent(s, principal, agent).id if agent else None,
            package_id=access_packages.get(s, package).id if package else None,
        )
        reached = reach.agent_ids(s, principal, *READ_ROLES)
        return [
            access_packages.assignment_dict(s, r)
            for r in rows
            if reached is None or r.agent_id in reached
        ]


@router.post("/v1/access-assignments", status_code=201, auth=signed_in)
def request_package(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Ask for an access package for an agent (``agent``, ``package``, ``days``,
    ``reason``); asked again while it holds one, it is a renewal. The agent's owner and
    sponsors, approvers, administrators and registrars ask; an administrator can assign it
    at once (``approve``)."""
    unknown = sorted(set(body) - {"agent", "package", "days", "reason", "approve"})
    if unknown:
        raise ValidationError(
            f"unknown field(s) {', '.join(unknown)}: send agent, package, days and reason"
        )
    for key in ("agent", "package"):
        if not isinstance(body.get(key), str) or not body[key]:
            raise ValidationError(f"{key} is required")
    approve = body.get("approve", False) is True
    principal = request.auth
    with runtime(request).db.session() as s:
        agent = agents.get(s, body["agent"])
        here = _in_reach(s, principal, agent, f"agent {body['agent']!r} not found")
        if not access_packages.may_request(s, here.roles, principal.person, agent):
            raise HTTPException(
                403,
                f"{agent.name}'s owner and sponsors, approvers and administrators ask for its "
                "access packages",
            )
        if approve and not here.is_admin:
            raise HTTPException(403, "only an administrator assigns an access package at once")
        row = access_packages.request(
            s,
            agent=agent,
            package=access_packages.get(s, body["package"]),
            days=body.get("days"),
            reason=body.get("reason"),
            actor=principal.actor,
            approve=approve,
        )
        return access_packages.assignment_dict(s, row)


@router.get("/v1/access-assignments/{assignment_id}", auth=signed_in)
def get_assignment(request: HttpRequest, assignment_id: str) -> dict[str, Any]:
    with runtime(request).db.session() as s:
        row = access_packages.assignment(s, assignment_id)
        missing = f"access assignment {assignment_id} not found"
        _may_read(s, request.auth, _agent(s, row), missing)
        return access_packages.assignment_dict(s, row)


def _agent(session: Any, row: AccessAssignment) -> Agent:
    agent = session.get(Agent, row.agent_id)
    if agent is None:
        raise NotFound(f"agent {row.agent_id} not found")
    return agent


@router.post("/v1/access-assignments/{assignment_id}/{action}", auth=signed_in)
def assignment_action(
    request: HttpRequest, assignment_id: str, action: str, body: dict[str, Any] = Body({})
) -> dict[str, Any]:
    """``approve`` and ``deny`` a request (approvers and administrators, never the person who
    asked); ``revoke`` what an agent holds (approvers and administrators, and the secops role
    from contain on); ``review`` it, with ``keep`` true or false (approvers, administrators,
    and the agent's owner and sponsors)."""
    if action not in ("approve", "deny", "revoke", "review"):
        raise NotFound(f"no action {action!r}: approve, deny, revoke or review")
    principal = request.auth
    with runtime(request).db.session() as s:
        row = access_packages.assignment(s, assignment_id)
        agent = _agent(s, row)
        # Their roles where the agent is: an approver for its team decides.
        here = _in_reach(s, principal, agent, f"access assignment {assignment_id} not found")
        deciders = bool(here.roles & access_packages.DECIDERS)
        if action in ("approve", "deny"):
            if not deciders:
                raise HTTPException(403, "approvers and administrators decide access requests")
            access_packages.decide(
                s, row, approve=action == "approve", actor=principal.actor, note=body.get("note")
            )
        elif action == "revoke":
            if not deciders:
                if "secops" not in here.roles:
                    raise HTTPException(403, "approvers and administrators revoke access")
                handoff.check(s, here, handoff.CONTAIN)
            access_packages.revoke(s, row, actor=principal.actor, reason=body.get("reason"))
        else:
            if not deciders and not _responsible(s, principal, agent):
                raise HTTPException(
                    403,
                    f"{agent.name}'s owner and sponsors, approvers and administrators review it",
                )
            keep = body.get("keep")
            if not isinstance(keep, bool):
                raise ValidationError("keep is true (it still needs it) or false (remove it)")
            access_packages.review(s, row, keep=keep, actor=principal.actor, note=body.get("note"))
        return access_packages.assignment_dict(s, row)


@router.get("/v1/agents/{ref}/access-packages", tags=["agents"], auth=signed_in)
def agent_packages(request: HttpRequest, ref: str) -> list[dict[str, Any]]:
    """The access packages an agent holds and has asked for, newest first."""
    principal = request.auth
    with runtime(request).db.session() as s:
        agent = agents.get(s, ref)
        _may_read(s, principal, agent, f"agent {ref!r} not found")
        return [
            access_packages.assignment_dict(s, r)
            for r in access_packages.assignments(s, agent_id=agent.id)
        ]
