"""Agents on other platforms (Microsoft 365, Copilot Studio) and the connector allowlist."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.identity.delegation import GRAPH, POWER_PLATFORM, DelegationError
from agentgov.platforms.microsoft import PlatformError
from agentgov.registry import agents, platforms

router = APIRouter(prefix="/v1/platforms", tags=["platforms"])
agent_router = APIRouter(prefix="/v1/agents", tags=["platforms"])
read = require(*READ_ROLES)
admin = require("admin")


def _as_signed_in_admin(rt: Any, principal: Principal, api: str) -> str:
    """An access token to act as this administrator in Microsoft, or a 409 saying why not."""
    if rt.delegations is None:
        raise HTTPException(
            409,
            "AgentGov is not set up to act in Microsoft 365 as a signed-in administrator "
            "(AGENTGOV_MICROSOFT_ADMIN_ACTIONS; see docs/platforms.md)",
        )
    if principal.session_id is None:
        raise HTTPException(
            409,
            "Microsoft accepts this only from a signed-in administrator: sign in to AgentGov "
            "with Microsoft Entra ID (in the CLI, `agentgov login`)",
        )
    try:
        return rt.delegations.access_token(principal.session_id, api)
    except DelegationError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("")
def overview(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """Each source of platform agents, how many it reported and how its last sync went."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        view = platforms.overview(s, m365_configured=rt.m365 is not None)
    # Whether signed-in administrators can act in Microsoft through AgentGov.
    return {**view, "admin_actions": rt.delegations is not None}


@router.post("/microsoft-365/sync")
def sync_microsoft_365(request: Request, principal: Principal = Depends(admin)) -> dict[str, int]:
    """Read the Microsoft 365 agent catalog now (it is also read on a schedule)."""
    rt = request.app.state.rt
    if rt.m365 is None:
        raise HTTPException(
            409,
            "Microsoft 365 sync is not configured: set AGENTGOV_M365_TENANT_ID, "
            "AGENTGOV_M365_CLIENT_ID and AGENTGOV_M365_CLIENT_SECRET",
        )
    try:
        return rt.sync_microsoft_365(actor=principal.actor)
    except PlatformError as exc:
        raise HTTPException(502, str(exc)) from exc


@router.post("/copilot-studio/import")
def import_copilot_studio(
    request: Request, payload: Any = Body(...), principal: Principal = Depends(admin)
) -> dict[str, int]:
    """Import Copilot Studio agents from a Power Platform inventory export (JSON)."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        counts = platforms.import_copilot_studio(s, payload, actor=principal.actor)
        platforms.refresh_risk(s, rt.settings)
        return counts


@router.post("/copilot-studio/sync")
def sync_copilot_studio(request: Request, principal: Principal = Depends(admin)) -> dict[str, int]:
    """Read the Copilot Studio inventory now, as the signed-in administrator."""
    rt = request.app.state.rt
    token = _as_signed_in_admin(rt, principal, POWER_PLATFORM)
    try:
        rows = rt.microsoft_admin.copilot_studio_agents(token)
    except PlatformError as exc:
        with rt.db.session() as s:
            platforms.set_sync(
                s, "copilot-studio", ok=False, counts={}, message=str(exc), actor=principal.actor
            )
        raise HTTPException(502, str(exc)) from exc
    with rt.db.session() as s:
        counts = platforms.import_copilot_studio(s, rows, actor=principal.actor)
        platforms.refresh_risk(s, rt.settings)
        return counts


@router.get("/connectors")
def connectors(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """Every connector Copilot Studio agents use, and whether it is on the allowlist."""
    with request.app.state.rt.db.session() as s:
        return platforms.connector_usage(s)


@router.put("/connectors/{connector_id}/approval")
def approve_connector(
    request: Request,
    connector_id: str,
    body: dict[str, Any] = Body(default={}),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    """Put a connector on the allowlist. Agents using others get a finding."""
    note = body.get("note") or ""
    if not isinstance(note, str):
        raise HTTPException(422, "note must be a string")
    rt = request.app.state.rt
    with rt.db.session() as s:
        platforms.approve_connector(s, connector_id, note=note, actor=principal.actor)
        platforms.refresh_risk(s, rt.settings)
    return {"connector_id": platforms.connector_key(connector_id), "approved": True}


@router.delete("/connectors/{connector_id}/approval")
def remove_approval(
    request: Request, connector_id: str, principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Take a connector off the allowlist."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        platforms.remove_approval(s, connector_id, actor=principal.actor)
        platforms.refresh_risk(s, rt.settings)
    return {"connector_id": platforms.connector_key(connector_id), "approved": False}


def _platform_block(request: Request, ref: str, principal: Principal, *, blocked: bool) -> dict:
    rt = request.app.state.rt
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        where = platforms.target(s, agent)
    api = POWER_PLATFORM if where["source"] == "copilot-studio" else GRAPH
    token = _as_signed_in_admin(rt, principal, api)
    try:
        if where["source"] == "copilot-studio":
            rt.microsoft_admin.quarantine(
                token, where["environment"], where["id"], quarantined=blocked
            )
        else:
            rt.microsoft_admin.block_package(token, where["id"], blocked=blocked)
    except PlatformError as exc:
        raise HTTPException(502, str(exc)) from exc
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        platforms.record_platform_block(s, agent, where, blocked=blocked, actor=principal.actor)
    return {"agent": agent.name, "platform": platforms.SOURCES[where["source"]], "blocked": blocked}


@agent_router.post("/{ref}/platform/block")
def platform_block(request: Request, ref: str, principal: Principal = Depends(admin)) -> dict:
    """Block the agent in its own platform, as the signed-in administrator: quarantine a
    Copilot Studio agent, or block a Microsoft 365 agent for the whole organisation."""
    return _platform_block(request, ref, principal, blocked=True)


@agent_router.post("/{ref}/platform/unblock")
def platform_unblock(request: Request, ref: str, principal: Principal = Depends(admin)) -> dict:
    """Undo a block in the agent's own platform, as the signed-in administrator."""
    return _platform_block(request, ref, principal, blocked=False)
