"""Registry endpoints: agents, blueprints, tool servers, policies and API keys."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from agentgov import ledger
from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.identity.keycloak import KeycloakError
from agentgov.models import ACTIVE
from agentgov.registry import (
    agents,
    apikeys,
    blueprints,
    features,
    identity_issuers,
    instructions,
    platforms,
    policies,
    toolservers,
)
from agentgov.registry.errors import Conflict
from agentgov.secops import handoff

router = APIRouter(prefix="/v1")

read = require(*READ_ROLES)
admin = require("admin")
# Kill switches: administrators, and the security team's tools as far as the hand-off lets them.
kill_switch = require("secops")


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
    _: Principal = Depends(read),
) -> list[dict[str, Any]]:
    """``source`` is ``registered``, ``discovered:<how>`` or ``platform:<platform>``."""
    with _rt(request).db.session() as s:
        return [
            agents.to_dict(a)
            for a in agents.list_agents(
                s,
                status=status,
                blueprint=blueprint,
                risk_level=risk_level,
                q=q,
                source=source,
                include_deleted=include_deleted,
            )
        ]


@router.post("/agents", status_code=201, tags=["agents"])
def register_agent(
    request: Request,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(require("registrar")),
) -> dict[str, Any]:
    """Register an agent. Admins may pass ``approve: true``; registrars always
    create ``pending`` agents that need approval (Agent 365 "requests")."""
    rt = _rt(request)
    requested = bool(body.pop("approve", False))
    text = body.pop("instructions", None)
    with rt.db.session() as s:
        if principal.is_admin:
            approve = requested
        else:
            approve = not features.is_on(s, "registration-approval")
        agent = agents.register(s, rt.settings, body, actor=principal.actor, approve=approve)
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
def get_agent(request: Request, ref: str, _: Principal = Depends(read)) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        agent = agents.get(s, ref)
        # What Microsoft 365 or Copilot Studio reports, for agents that run there.
        return {**agents.to_dict(agent), "platforms": platforms.for_agent(s, agent.id)}


@router.get("/agents/{ref}/a2a", tags=["agents"])
def agent_a2a(request: Request, ref: str, _: Principal = Depends(read)) -> dict[str, Any]:
    """Agent to agent: where other agents call it through the gateway, whom it may call,
    and who may call it."""
    rt = _rt(request)
    with rt.db.session() as s:
        return agents.a2a_view(s, rt.settings, agents.get(s, ref))


@router.patch("/agents/{ref}", tags=["agents"])
def update_agent(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        agent = agents.get(s, ref)
        agents.update(s, agent, body, actor=principal.actor)
        return agents.to_dict(agent)


@router.post("/agents/{ref}/attest", tags=["agents"])
def attest_agent(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(default={}),
    principal: Principal = Depends(require("approver")),
) -> dict[str, Any]:
    """A sponsor confirms the agent is still needed (periodic access review)."""
    with _rt(request).db.session() as s:
        agent = agents.get(s, ref)
        if not principal.is_admin and principal.name not in (agent.sponsors or []):
            raise HTTPException(403, "only the agent's sponsors or an admin can attest")
        agents.attest(s, agent, actor=principal.actor, note=body.get("note"))
        return agents.to_dict(agent)


@router.post("/agents/{ref}/credentials", tags=["agents"])
def agent_credentials(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(default={}),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    """Return the agent's OAuth client credentials (``rotate: true`` issues a new secret), or,
    for an agent with a workload identity, what token authenticates it instead."""
    rt = _rt(request)
    if rt.identity is None:
        raise HTTPException(409, "identity provider integration is not configured")
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        if agent.status != ACTIVE:
            raise Conflict("credentials are only issued to active agents")
        if agent.workload_issuer and body.get("rotate"):
            raise Conflict(
                "the agent has no secret to rotate: it authenticates with its workload identity"
            )
        try:
            creds = rt.identity.credentials(agent, rotate=bool(body.get("rotate")))
        except KeycloakError as exc:
            raise HTTPException(502, f"identity provider error: {exc}") from exc
        if rt.settings.keycloak_issuer:
            creds["token_endpoint"] = (
                rt.settings.keycloak_issuer.rstrip("/") + "/protocol/openid-connect/token"
            )
        creds["audience"] = rt.settings.gateway_audience
        if creds.get("method") == "workload-identity":
            # What its issuer's token must look like to authenticate it. Nothing here is
            # secret, so reading it isn't recorded.
            issuer = identity_issuers.get(s, creds["issuer"])
            creds["assertion_type"] = identity_issuers.assertion_type(issuer)
            creds["assertion_audience"] = issuer.audience or rt.settings.keycloak_issuer
            return creds
        ledger.append(
            s,
            type="agent.credentials_rotated" if body.get("rotate") else "agent.credentials_read",
            actor=principal.actor,
            agent=agent,
            severity="warning",
        )
        return creds


@router.post("/agents/{ref}/{action}", tags=["agents"])
def agent_lifecycle(
    request: Request,
    ref: str,
    action: str,
    body: dict[str, Any] = Body(default={}),
    principal: Principal = Depends(kill_switch),
) -> dict[str, Any]:
    """Lifecycle actions: approve, block (kill switch), unblock, delete (soft), restore, adopt."""
    rt = _rt(request)
    with rt.db.session() as s:
        handoff.check_kill_switch(s, principal, action)
        agent = agents.get(s, ref)
        if action == "adopt" and body:
            agents.update(
                s, agent, {k: v for k, v in body.items() if k != "reason"}, actor=principal.actor
            )
        agents.transition(
            s, rt.settings, agent, action, actor=principal.actor, reason=body.get("reason")
        )
        return agents.to_dict(agent)


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
def agent_risk(request: Request, ref: str, _: Principal = Depends(read)) -> dict[str, Any]:
    """The agent's current risk, as last computed from decisions and posture scans."""
    with _rt(request).db.session() as s:
        return agents.to_dict(agents.get(s, ref))["risk"]


@router.post("/agents/{ref}/risk/refresh", tags=["agents"])
def refresh_agent_risk(request: Request, ref: str, _: Principal = Depends(admin)) -> dict[str, Any]:
    """Recompute risk now. May raise findings and, with auto-block enabled, block the agent."""
    rt = _rt(request)
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        result = agents.refresh_risk(s, rt.settings, agent)
        return {"score": result.score, "level": result.level, "factors": result.factors}


# ------------------------------------------------------------------- blueprints


@router.get("/blueprints", tags=["blueprints"])
def list_blueprints(request: Request, _: Principal = Depends(read)) -> list[dict[str, Any]]:
    with _rt(request).db.session() as s:
        return [blueprints.to_dict(b) for b in blueprints.list_all(s)]


@router.post("/blueprints", status_code=201, tags=["blueprints"])
def create_blueprint(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(admin)
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        return blueprints.to_dict(blueprints.create(s, body, actor=principal.actor))


@router.get("/blueprints/{ref}", tags=["blueprints"])
def get_blueprint(request: Request, ref: str, _: Principal = Depends(read)) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        return blueprints.to_dict(blueprints.get(s, ref))


@router.patch("/blueprints/{ref}", tags=["blueprints"])
def update_blueprint(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        bp = blueprints.get(s, ref)
        blueprints.update(s, bp, body, actor=principal.actor)
        return blueprints.to_dict(bp)


@router.delete("/blueprints/{ref}", tags=["blueprints"])
def delete_blueprint(
    request: Request, ref: str, principal: Principal = Depends(admin)
) -> dict[str, str]:
    with _rt(request).db.session() as s:
        blueprints.delete(s, blueprints.get(s, ref), actor=principal.actor)
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
    with rt.db.session() as s:
        ts = toolservers.get(s, ref)
        toolservers.update(s, ts, body, actor=principal.actor)
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
    request: Request, ref: str, action: str, principal: Principal = Depends(kill_switch)
) -> dict[str, Any]:
    """approve (pending review), block, unblock."""
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
        policies.update(s, policy, body, actor=principal.actor)
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
    with _rt(request).db.session() as s:
        return [apikeys.to_dict(k) for k in apikeys.list_all(s)]


@router.post("/apikeys", status_code=201, tags=["apikeys"])
def create_apikey(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(admin)
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        key, token = apikeys.create(
            s, name=body.get("name", ""), role=body.get("role", ""), actor=principal.actor
        )
        return {**apikeys.to_dict(key), "token": token}


@router.delete("/apikeys/{key_id}", tags=["apikeys"])
def revoke_apikey(
    request: Request, key_id: str, principal: Principal = Depends(admin)
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        return apikeys.to_dict(apikeys.revoke(s, key_id, actor=principal.actor))
