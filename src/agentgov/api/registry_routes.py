"""Registry endpoints: agents, blueprints, tool servers, policies and API keys."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select

from agentgov import ledger
from agentgov.api import reach
from agentgov.api.auth import READ_ROLES, Principal, require, signed_in
from agentgov.api.versions import if_match
from agentgov.identity.keycloak import KeycloakError
from agentgov.models import ACTIVE, PlatformAgent
from agentgov.registry import (
    agents,
    apikeys,
    blueprints,
    bulk,
    classification,
    features,
    identity_issuers,
    instructions,
    people,
    platforms,
    policies,
    teams,
    toolservers,
    validation,
)
from agentgov.registry.errors import Conflict, NotFound
from agentgov.registry.validation import known_fields
from agentgov.secops import handoff

# What an agent's body takes besides its name: the fields an edit changes, and its
# identity from an issuer of its own.
AGENT_FIELDS = {*agents.EDITABLE, "workload_identity"}
router = APIRouter(prefix="/v1")

read = require(*READ_ROLES)
admin = require("admin")
# Kill switches: administrators, and the security team's tools as far as the hand-off lets them
# (for the agents of their teams, when their role is for some teams only). A tool server,
# which every team's agents use, only by roles for every team.
kill_switch = reach.require("secops")
org_kill_switch = require("secops")


def _rt(request: Request) -> Any:
    return request.app.state.rt


# ----------------------------------------------------------------------- agents


@router.get("/agents", tags=["agents"])
def list_agents(
    request: Request,
    status: str | None = None,
    blueprint: str | None = None,
    risk_level: str | None = None,
    q: str | None = None,
    source: str | None = None,
    include_deleted: bool = False,
    principal: Principal = Depends(reach.read),
) -> list[dict[str, Any]]:
    """``source`` is ``registered``, ``discovered:<how>`` or ``platform:<platform>``. Someone
    with roles for some teams only sees those teams' agents."""
    with _rt(request).db.session() as s:
        listed = agents.list_agents(
            s,
            status=status,
            blueprint=blueprint,
            risk_level=risk_level,
            q=q,
            source=source,
            include_deleted=include_deleted,
        )
        reached = reach.agent_ids(s, principal, *READ_ROLES)
        if reached is not None:
            listed = [a for a in listed if a.id in reached]
        # Who made each agent found on a platform, as its platform says.
        makers = people.for_records(
            s,
            list(
                s.scalars(
                    select(PlatformAgent).where(
                        PlatformAgent.agent_id.in_([a.id for a in listed if a.on_platform])
                    )
                )
            ),
        )
        rows = [
            {
                **agents.to_dict(a),
                **({"maker": people.shown(makers[a.id])} if a.id in makers else {}),
            }
            for a in listed
        ]
        reach.mark(rows, s, principal)
        return rows


@router.post("/agents", status_code=201, tags=["agents"])
def register_agent(
    request: Request,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(reach.require("registrar")),
) -> dict[str, Any]:
    """Register an agent. Admins may pass ``approve: true``; registrars always
    create ``pending`` agents that need approval (Agent 365 "requests"). A registrar or an
    admin for some teams only registers into one of them (``team``; their team, when they
    have one), an admin for it approving as admins do."""
    rt = _rt(request)
    # Where it comes from is the server's to say: registered.
    known_fields(body, AGENT_FIELDS | {"name", "approve", "instructions"}, "an agent")
    requested = bool(body.pop("approve", False))
    text = body.pop("instructions", None)
    with rt.db.session() as s:
        own = reach.teams(principal, "registrar")
        if own is not None and not body.get("team") and len(own) == 1:
            body["team"] = next(iter(own))  # their one team
        team = str(body.get("team") or "").lower()
        admin_there = principal.is_admin or team in {
            name.lower() for name in principal.teams.get("admin", ())
        }
        approve = requested if admin_there else not features.is_on(s, "registration-approval")
        # Its reserved labels: administrators' for every team (admin).
        with _unnamed(s, principal):
            agent = agents.register(
                s,
                rt.settings,
                body,
                actor=principal.actor,
                approve=approve,
                admin=principal.is_admin,
            )
        reach.keep(s, principal, agent, "registrar")
        # Put to work at once by a role for some teams only (an administrator for the team, or
        # a registrar while registration approval is off): with what its blueprint grants.
        every_team = principal.is_admin if admin_there else "registrar" in principal.roles
        if approve and not every_team:
            reach.within_blueprint(agent)
        if text is not None:
            instructions.report(
                s,
                agent,
                source="registered",
                text=text,
                actor=principal.actor,
                classify=rt.guardian is not None,
            )
            agents.refresh_risk(s, rt.settings, agent)
        return agents.to_dict(agent)


@router.get("/agents/{ref}", tags=["agents"])
def get_agent(
    request: Request, ref: str, principal: Principal = Depends(reach.read)
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        agent = agents.get(s, ref)
        reach.check(s, principal, agent, *READ_ROLES, ref=ref)
        makers = people.for_agent(s, agent.id)
        row = {
            **agents.to_dict(agent),
            # What Microsoft 365 or Copilot Studio reports, for agents that run there.
            "platforms": platforms.for_agent(s, agent.id),
            # Blocked in AgentGov, the platform that still runs it, if one does.
            "still_runs_in": platforms.still_runs_in(s, agent),
            # Who made it and owns it there, and whom adopting it would make its owner.
            "makers": makers,
            "suggested_owner": people.suggested(makers),
            # Its owner and sponsors who have left (docs/issues.md#people-who-leave).
            "left": people.who_left(s, agent),
            # The controls whose mode differs for it, and why (docs/features.md#exceptions).
            "control_modes": features.exceptions_for(
                agent, features.modes(s), features.all_scopes(s)
            ),
        }
        reach.mark([row], s, principal)
        return row


@router.get("/agents/{ref}/a2a", tags=["agents"])
def agent_a2a(
    request: Request, ref: str, principal: Principal = Depends(reach.read)
) -> dict[str, Any]:
    """Agent to agent: where other agents call it through the gateway, whom it may call,
    and who may call it."""
    rt = _rt(request)
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        reach.check(s, principal, agent, *READ_ROLES, ref=ref)
        reached = reach.agent_ids(s, principal, *READ_ROLES)
        return agents.a2a_view(s, rt.settings, agent, reached=reached)


@router.patch("/agents/{ref}", tags=["agents"])
def update_agent(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(reach.require("admin")),
) -> dict[str, Any]:
    rt = _rt(request)
    known_fields(body, AGENT_FIELDS, "an agent's edit")
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        reach.check(s, principal, agent, "admin", ref=ref)
        _exemptions(principal, agent, body)
        hold = reach.Hold(s, principal)
        hold.before(agent)
        with _unnamed(s, principal):
            changed = agents.update(
                s, agent, body, actor=principal.actor, version=if_match(request)
            )
        reach.keep(s, principal, agent, "admin")
        hold.check(agent)
        if set(changed) & agents.RISKY_FIELDS:
            agents.refresh_risk(s, rt.settings, agent)
        return agents.to_dict(agent)


@contextmanager
def _unnamed(session: Any, principal: Principal) -> Iterator[None]:
    """The agent that already has a workload identity asked for is named only to whoever
    reaches it."""
    try:
        yield
    except identity_issuers.Taken as exc:
        if reach.reaches(session, principal, exc.agent, *READ_ROLES):
            raise
        raise Conflict("another agent already has this workload identity") from None


def _exemptions(principal: Principal, agent: Any, body: dict[str, Any]) -> None:
    """Refuse an administrator for some teams only a change to the reserved labels (those that
    exempt an agent from rules or controls, and those the policies read as an allowance):
    those are for administrators for every team. No labels at all removes them too."""
    if principal.is_admin or "labels" not in body:
        return
    changed = agents.reserved_changes(agent.labels, validation.labels(body["labels"]))
    if changed:
        raise HTTPException(
            403,
            f"label(s) {', '.join(changed)}: {agents.RESERVED_WORDS} are set by administrators "
            "for every team",
        )


def _sponsors(agent: Any, principal: Principal) -> bool:
    """Whether ``principal`` is one of the agent's sponsors: a person signed in as themselves
    (Principal.person), whatever their role. An API key is nobody, whatever its name."""
    person = principal.person
    return person is not None and person.lower() in {str(s).lower() for s in agent.sponsors or []}


@router.post("/agents/{ref}/attest", tags=["agents"])
def attest_agent(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(default={}),
    principal: Principal = Depends(signed_in),
) -> dict[str, Any]:
    """A sponsor confirms the agent is still needed (periodic access review): its sponsors,
    whatever their role in AgentGov, and administrators."""
    refused = "only the agent's sponsors or an admin can attest"
    with _rt(request).db.session() as s:
        try:
            agent = agents.get(s, ref)
        except NotFound:
            # Which agents exist is for those who may read them.
            if principal.roles & set(READ_ROLES):
                raise
            raise HTTPException(403, refused) from None
        admin_here = "admin" in reach.roles_at(s, principal, agent)
        if not admin_here and not _sponsors(agent, principal):
            raise HTTPException(403, refused)
        agents.attest(s, agent, actor=principal.actor, note=body.get("note"))
        return agents.to_dict(agent)


def _straight_to_the_gateway(s: Any, agent: Any, settings: Any) -> dict[str, str] | None:
    """How an agent calls the gateway with its own token, where the gateway takes its
    identity issuer's (docs/agent-identity.md#straight-to-the-gateway): the token its issuer
    gives it, for this audience, as the bearer token. None where it doesn't."""
    for issuer in identity_issuers.at_the_gateway(s) if agent.workload_issuer else ():
        if issuer.name == agent.workload_issuer:
            return {
                "url": settings.gateway_public_url,
                "issuer": issuer.issuer,
                "audience": issuer.audience or settings.gateway_audience,
            }
    return None


@router.post("/agents/{ref}/credentials", tags=["agents"])
def agent_credentials(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(default={}),
    principal: Principal = Depends(reach.require("admin")),
) -> dict[str, Any]:
    """Return the agent's OAuth client credentials (``rotate: true`` issues a new secret);
    for an agent with a workload identity, what token authenticates it instead (and how it
    calls the gateway with that token itself, where the gateway takes its issuer's); and for
    a public client, where people sign in to it."""
    rt = _rt(request)
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        reach.check(s, principal, agent, "admin", ref=ref)
        if agent.status != ACTIVE:
            raise Conflict("credentials are only issued to active agents")
        if agent.workload_issuer and body.get("rotate"):
            raise Conflict(
                "the agent has no secret to rotate: it authenticates with its workload identity"
            )
        if agents.identity_method(agent) == "sign-in" and body.get("rotate"):
            raise Conflict("a public client has no secret to rotate: people sign in to it")
        direct = _straight_to_the_gateway(s, agent, rt.settings)
        if rt.identity is None:
            if direct is None:
                raise HTTPException(409, "identity provider integration is not configured")
            # No Keycloak: its issuer's token goes to the gateway as it is.
            return {
                "method": "workload-identity",
                "issuer": agent.workload_issuer,
                "subject": agent.workload_subject or "",
                "gateway": direct,
            }
        try:
            creds = rt.identity.credentials(agent, rotate=bool(body.get("rotate")))
        except KeycloakError as exc:
            raise HTTPException(502, f"identity provider error: {exc}") from exc
        if rt.settings.keycloak_issuer:
            creds["token_endpoint"] = (
                rt.settings.keycloak_issuer.rstrip("/") + "/protocol/openid-connect/token"
            )
        creds["audience"] = rt.settings.gateway_audience
        if creds.get("method") == "sign-in":
            # Where people sign in to it: nothing here is secret, so reading it isn't
            # recorded.
            creds["authorization_endpoint"] = (
                str(creds["issuer"]).rstrip("/") + "/protocol/openid-connect/auth"
            )
            return creds
        if creds.get("method") == "workload-identity":
            # What its issuer's token must look like to authenticate it. Nothing here is
            # secret, so reading it isn't recorded.
            issuer = identity_issuers.get(s, creds["issuer"])
            creds["assertion_type"] = identity_issuers.assertion_type(issuer)
            creds["assertion_audience"] = issuer.audience or rt.settings.keycloak_issuer
            if direct is not None:
                creds["gateway"] = direct
            return creds
        ledger.append(
            s,
            type="agent.credentials_rotated" if body.get("rotate") else "agent.credentials_read",
            actor=principal.actor,
            agent=agent,
            severity="warning",
        )
        return creds


@router.post("/agents/adopt", tags=["agents"])
def adopt_agents(
    request: Request,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(reach.require("admin")),
) -> dict[str, Any]:
    """Adopt agents found on platforms at once (``{"agents": [...]}``): with ``makers:
    true``, each agent's maker on its platform as owner and sponsor, where AgentGov knows
    them; ``owner`` and ``sponsors`` for the others. Those it can't adopt are left, each
    with why. An administrator for some teams only adopts those teams' agents."""
    refs = body.get("agents")
    sponsors = body.get("sponsors")
    if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
        raise HTTPException(422, "agents is a list of agents' names or IDs")
    if sponsors is not None and (
        not isinstance(sponsors, list) or not all(isinstance(x, str) for x in sponsors)
    ):
        raise HTTPException(422, "sponsors is a list of email addresses")
    owner = body.get("owner")
    if owner is not None and not isinstance(owner, str):
        raise HTTPException(422, "owner is a team or a person's email address")
    reason = body.get("reason")
    rt = _rt(request)
    with rt.db.session() as s:
        return people.adopt(
            s,
            rt.settings,
            refs,
            owner=(owner or "").strip() or None,
            sponsors=sponsors or None,
            makers=bool(body.get("makers")),
            actor=principal.actor,
            reason=reason if isinstance(reason, str) else None,
            reached=reach.agent_ids(s, principal, "admin"),
        )


@router.put("/agents/{ref}/classification", tags=["agents"])
def classify_agent(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(reach.require("approver")),
) -> dict[str, Any]:
    """Classify an agent under the EU AI Act: ``category``, ``role``, ``basis`` and
    ``purpose`` (docs/evidence.md#a-classification-register). Approvers and administrators."""
    with _rt(request).db.session() as s:
        agent = agents.get(s, ref)
        reach.check(s, principal, agent, "approver", ref=ref)
        classification.classify(s, agent, body, actor=principal.actor)
        return agents.to_dict(agent)


@router.delete("/agents/{ref}/classification", tags=["agents"])
def unclassify_agent(
    request: Request, ref: str, principal: Principal = Depends(reach.require("approver"))
) -> dict[str, Any]:
    """The agent is no longer classified: it shows as such in the register."""
    with _rt(request).db.session() as s:
        agent = agents.get(s, ref)
        reach.check(s, principal, agent, "approver", ref=ref)
        classification.classify(s, agent, None, actor=principal.actor)
        return agents.to_dict(agent)


@router.post("/agents/bulk", tags=["agents"])
def bulk_agents(
    request: Request,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(reach.require("secops", "approver")),
) -> dict[str, Any]:
    """Do one thing to many agents (``agents``, by name or ID) at once: a lifecycle
    ``action`` (approve, block, unblock, delete or restore); ``update`` with ``fields``
    (owner, team, sponsors, add_sponsors, remove_sponsors, blueprint, environment,
    risk_tier); or ``classify`` with ``fields`` (category, role, basis, purpose). Each on
    its own: those it can't do are ``left``, each with why. The secops role blocks and
    unblocks, as far as the hand-off lets it; approvers classify."""
    unknown = sorted(set(body) - {"action", "agents", "reason", "fields"})
    if unknown:
        raise HTTPException(
            422, f"unknown field(s) {', '.join(unknown)}: send action, agents, reason and fields"
        )
    action = str(body.get("action") or "")
    reason = body.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise HTTPException(422, "reason is text")
    if action not in bulk.AGENT_ACTIONS:
        raise HTTPException(422, f"action is {', '.join(bulk.AGENT_ACTIONS)}")
    role = {"update": "admin", "classify": "approver"}.get(action, "secops")
    rt = _rt(request)
    with rt.db.session() as s:
        if reach.teams(principal, role) == frozenset():
            raise HTTPException(403, f"role {principal.role!r} may not do this")
        check = None
        # An edit loosens nothing for a role for some teams only (reach.Hold).
        hold = reach.Hold(s, principal) if action == "update" else None
        if role == "secops":
            if principal.teams:
                # What the kill switch lets them do, by their roles where each agent is.
                def check(agent: Any) -> None:
                    handoff.check_kill_switch(s, reach.here(s, principal, agent), action)
                    if action == "approve" and not principal.is_admin:
                        reach.within_blueprint(agent)
            else:
                handoff.check_kill_switch(s, principal, action)
        elif hold is not None:
            check = hold.before

        def keep(agent: Any) -> None:
            reach.keep(s, principal, agent, role)
            if hold is not None:
                hold.check(agent)

        return bulk.agents(
            s,
            rt.settings,
            body.get("agents"),
            action,
            actor=principal.actor,
            reason=(reason or "").strip() or None,
            fields=body.get("fields"),
            reached=reach.agent_ids(s, principal, role),
            check=check,
            keep=keep,
        )


@router.post("/agents/{ref}/{action}", tags=["agents"])
def agent_lifecycle(
    request: Request,
    ref: str,
    action: str,
    body: dict[str, Any] = Body(default={}),
    principal: Principal = Depends(kill_switch),
) -> dict[str, Any]:
    """Lifecycle actions: approve, block (kill switch), unblock, delete (soft), restore, adopt.
    Those with roles for some teams only, for those teams' agents."""
    rt = _rt(request)
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        reach.check(s, principal, agent, "secops", ref=ref)
        handoff.check_kill_switch(s, reach.here(s, principal, agent), action)
        if action == "approve" and not principal.is_admin:
            reach.within_blueprint(agent)  # an administrator for its team only
        if action == "adopt" and body:
            _exemptions(principal, agent, body)
            hold = reach.Hold(s, principal)
            hold.before(agent)
            with _unnamed(s, principal):
                agents.update(
                    s,
                    agent,
                    {k: v for k, v in body.items() if k != "reason"},
                    actor=principal.actor,
                )
            reach.keep(s, principal, agent, "admin")
            hold.check(agent)
        agents.transition(
            s, rt.settings, agent, action, actor=principal.actor, reason=body.get("reason")
        )
        if action in ("adopt", "approve", "restore"):
            # Its owner, sponsors and status count towards its risk: shown at once.
            agents.refresh_risk(s, rt.settings, agent)
        if agent.on_platform:
            # Those waiting to be reviewed on their platforms: blocked or deleted, they aren't.
            platforms.review_summary(s)
        # Blocked here, it may still run on its platform: an issue asks its people to stop it.
        return {**agents.to_dict(agent), "still_runs_in": platforms.still_runs_in(s, agent)}


@router.delete("/agents/{ref}", tags=["agents"])
def purge_agent(
    request: Request, ref: str, principal: Principal = Depends(admin)
) -> dict[str, str]:
    """Permanently remove a soft-deleted agent and its identity."""
    rt = _rt(request)
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        if rt.identity is not None and agent.status == "deleted":
            try:
                rt.identity.delete(agent)
            except KeycloakError as exc:
                raise HTTPException(502, f"identity provider error: {exc}") from exc
        agents.purge(s, agent, actor=principal.actor)
        return {"purged": ref}


@router.get("/agents/{ref}/risk", tags=["agents"])
def agent_risk(
    request: Request, ref: str, principal: Principal = Depends(reach.read)
) -> dict[str, Any]:
    """The agent's current risk, as last computed from decisions and posture scans."""
    with _rt(request).db.session() as s:
        agent = agents.get(s, ref)
        reach.check(s, principal, agent, *READ_ROLES, ref=ref)
        return agents.to_dict(agent)["risk"]


@router.post("/agents/{ref}/risk/refresh", tags=["agents"])
def refresh_agent_risk(
    request: Request, ref: str, principal: Principal = Depends(reach.require("admin"))
) -> dict[str, Any]:
    """Recompute risk now. May raise findings and, with auto-block enabled, block the agent."""
    rt = _rt(request)
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        reach.check(s, principal, agent, "admin", ref=ref)
        result = agents.refresh_risk(s, rt.settings, agent)
        return {"score": result.score, "level": result.level, "factors": result.factors}


# ------------------------------------------------------------------- blueprints


@router.get("/blueprints", tags=["blueprints"])
def list_blueprints(request: Request, _: Principal = Depends(reach.read)) -> list[dict[str, Any]]:
    """Every blueprint, for everyone who reads AgentGov (for some teams too)."""
    with _rt(request).db.session() as s:
        return [blueprints.to_dict(b) for b in blueprints.list_all(s)]


@router.post("/blueprints", status_code=201, tags=["blueprints"])
def create_blueprint(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(admin)
) -> dict[str, Any]:
    known_fields(body, {"name", *blueprints.FIELDS}, "a blueprint")
    with _rt(request).db.session() as s:
        return blueprints.to_dict(blueprints.create(s, body, actor=principal.actor))


@router.get("/blueprints/{ref}", tags=["blueprints"])
def get_blueprint(request: Request, ref: str, _: Principal = Depends(reach.read)) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        return blueprints.to_dict(blueprints.get(s, ref))


@router.patch("/blueprints/{ref}", tags=["blueprints"])
def update_blueprint(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    known_fields(body, blueprints.FIELDS, "a blueprint's edit")
    with _rt(request).db.session() as s:
        bp = blueprints.get(s, ref)
        blueprints.update(s, bp, body, actor=principal.actor, version=if_match(request))
        return blueprints.to_dict(bp)


@router.delete("/blueprints/{ref}", tags=["blueprints"])
def delete_blueprint(
    request: Request, ref: str, principal: Principal = Depends(admin)
) -> dict[str, str]:
    with _rt(request).db.session() as s:
        blueprints.delete(s, blueprints.get(s, ref), actor=principal.actor)
        return {"deleted": ref}


# ------------------------------------------------------------------------ teams


@router.get("/teams", tags=["teams"])
def list_teams(
    request: Request, principal: Principal = Depends(reach.read)
) -> list[dict[str, Any]]:
    """The teams: for someone with roles for some teams only, those."""
    mine = reach.teams(principal, *READ_ROLES)
    with _rt(request).db.session() as s:
        return [
            teams.to_dict(t)
            for t in teams.list_all(s)
            if mine is None or t.name.lower() in {n.lower() for n in mine}
        ]


@router.post("/teams", status_code=201, tags=["teams"])
def create_team(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """People and chat channels that own agents, and that issues escalate to."""
    with _rt(request).db.session() as s:
        return teams.to_dict(teams.create(s, body, actor=principal.actor))


@router.get("/teams/{ref}", tags=["teams"])
def get_team(
    request: Request, ref: str, principal: Principal = Depends(reach.read)
) -> dict[str, Any]:
    mine = reach.teams(principal, *READ_ROLES)
    with _rt(request).db.session() as s:
        team = teams.get(s, ref)
        if mine is not None and team.name.lower() not in {n.lower() for n in mine}:
            raise NotFound(f"team {ref!r} not found")
        reached = reach.agent_ids(s, principal, *READ_ROLES)
        return {**teams.to_dict(team), "named_by": teams.users(s, team.name, reached=reached)}


@router.patch("/teams/{ref}", tags=["teams"])
def update_team(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        team = teams.get(s, ref)
        teams.update_team(s, team, body, actor=principal.actor, version=if_match(request))
        return teams.to_dict(team)


@router.delete("/teams/{ref}", tags=["teams"])
def delete_team(
    request: Request, ref: str, principal: Principal = Depends(admin)
) -> dict[str, str]:
    with _rt(request).db.session() as s:
        teams.delete(s, teams.get(s, ref), actor=principal.actor)
        return {"deleted": ref}


# ---------------------------------------------------------------- tool servers


@router.get("/toolservers", tags=["toolservers"])
def list_toolservers(
    request: Request, status: str | None = None, _: Principal = Depends(read)
) -> list[dict[str, Any]]:
    rt = _rt(request)
    with rt.db.session() as s:
        return [
            toolservers.to_dict(t, rt.settings.gateway_public_url)
            for t in toolservers.list_all(s, status=status)
        ]


@router.post("/toolservers", status_code=201, tags=["toolservers"])
def create_toolserver(
    request: Request,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(require("registrar")),
) -> dict[str, Any]:
    """Register an MCP server. Registrar requests start ``pending`` review
    (Agent 365's bring-your-own MCP server approval flow)."""
    rt = _rt(request)
    known_fields(body, {"name", *toolservers.FIELDS}, "a tool server")
    with rt.db.session() as s:
        ts = toolservers.create(s, body, actor=principal.actor, approve=principal.is_admin)
        return toolservers.to_dict(ts, rt.settings.gateway_public_url)


@router.get("/toolservers/{ref}", tags=["toolservers"])
def get_toolserver(request: Request, ref: str, _: Principal = Depends(read)) -> dict[str, Any]:
    rt = _rt(request)
    with rt.db.session() as s:
        return toolservers.to_dict(toolservers.get(s, ref), rt.settings.gateway_public_url)


@router.patch("/toolservers/{ref}", tags=["toolservers"])
def update_toolserver(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    rt = _rt(request)
    known_fields(body, toolservers.FIELDS, "a tool server's edit")
    with rt.db.session() as s:
        ts = toolservers.get(s, ref)
        toolservers.update(s, ts, body, actor=principal.actor, version=if_match(request))
        return toolservers.to_dict(ts, rt.settings.gateway_public_url)


@router.delete("/toolservers/{ref}", tags=["toolservers"])
def delete_toolserver(
    request: Request, ref: str, principal: Principal = Depends(admin)
) -> dict[str, str]:
    with _rt(request).db.session() as s:
        toolservers.delete(s, toolservers.get(s, ref), actor=principal.actor)
        return {"deleted": ref}


@router.post("/toolservers/{ref}/tools/{tool}/approve", tags=["toolservers"])
def approve_tool(
    request: Request, ref: str, tool: str, principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Accept a changed tool definition (clears rug-pull protection for it)."""
    with _rt(request).db.session() as s:
        return toolservers.approve_tool(s, toolservers.get(s, ref), tool, actor=principal.actor)


@router.post("/toolservers/{ref}/{action}", tags=["toolservers"])
def toolserver_action(
    request: Request, ref: str, action: str, principal: Principal = Depends(org_kill_switch)
) -> dict[str, Any]:
    """approve (pending approval), block, unblock."""
    rt = _rt(request)
    with rt.db.session() as s:
        handoff.check_kill_switch(s, principal, action)
        ts = toolservers.set_status(s, toolservers.get(s, ref), action, actor=principal.actor)
        return toolservers.to_dict(ts, rt.settings.gateway_public_url)


# --------------------------------------------------------------------- policies


@router.get("/policies", tags=["policies"])
def list_policies(request: Request, _: Principal = Depends(read)) -> list[dict[str, Any]]:
    with _rt(request).db.session() as s:
        return [policies.to_dict(p) for p in policies.list_all(s)]


@router.post("/policies", status_code=201, tags=["policies"])
def create_policy(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(admin)
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        return policies.to_dict(policies.create(s, body, actor=principal.actor))


@router.get("/policies/{ref}", tags=["policies"])
def get_policy(request: Request, ref: str, _: Principal = Depends(read)) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        return policies.to_dict(policies.get(s, ref))


@router.put("/policies/{ref}", tags=["policies"])
def update_policy(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        policy = policies.get(s, ref)
        policies.update(s, policy, body, actor=principal.actor, version=if_match(request))
        return policies.to_dict(policy)


@router.delete("/policies/{ref}", tags=["policies"])
def delete_policy(
    request: Request, ref: str, principal: Principal = Depends(admin)
) -> dict[str, str]:
    with _rt(request).db.session() as s:
        policies.delete(s, policies.get(s, ref), actor=principal.actor)
        return {"deleted": ref}


# --------------------------------------------------------------------- api keys


@router.get("/apikeys", tags=["apikeys"])
def list_apikeys(request: Request, _: Principal = Depends(read)) -> list[dict[str, Any]]:
    """Every key's name, role, prefix and use (never the key): readable for access reviews."""
    rt = _rt(request)
    with rt.db.session() as s:
        return [apikeys.to_dict(k, rt.settings.api_key_max_days) for k in apikeys.list_all(s)]


@router.post("/apikeys", status_code=201, tags=["apikeys"])
def create_apikey(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """A new key: ``expires_in_days`` days (AGENTGOV_API_KEY_DAYS when left out; null: it
    never expires, unless AGENTGOV_API_KEY_MAX_DAYS says keys must)."""
    known_fields(body, {"name", "role", "expires_in_days", "team"}, "an API key")
    rt = _rt(request)
    settings = rt.settings
    days = apikeys.lifetime(
        body.get("expires_in_days", settings.api_key_days), max_days=settings.api_key_max_days
    )
    with rt.db.session() as s:
        key, token = apikeys.create(
            s,
            name=body.get("name", ""),
            role=body.get("role", ""),
            actor=principal.actor,
            days=days,
            team=body.get("team"),
        )
        return {**apikeys.to_dict(key, settings.api_key_max_days), "token": token}


@router.delete("/apikeys/{key_id}", tags=["apikeys"])
def revoke_apikey(
    request: Request, key_id: str, principal: Principal = Depends(admin)
) -> dict[str, Any]:
    rt = _rt(request)
    with rt.db.session() as s:
        key = apikeys.revoke(s, key_id, actor=principal.actor)
        return apikeys.to_dict(key, rt.settings.api_key_max_days)
