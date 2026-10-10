"""Agents on other platforms (Microsoft 365, Copilot Studio) and the connector allowlist."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.platforms.microsoft import PlatformError
from agentgov.registry import platforms

router = APIRouter(prefix="/v1/platforms", tags=["platforms"])
read = require(*READ_ROLES)
admin = require("admin")


@router.get("")
def overview(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """Each source of platform agents, how many it reported and how its last sync went."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        return platforms.overview(s, m365_configured=rt.m365 is not None)


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
