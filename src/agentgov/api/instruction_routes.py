"""An agent's instructions (system prompts) and what scanning finds in them. The check of
instructions that aren't stored is on Django (agentgov.web.instructions); these routes move
there with the registry's agent routes, whose paths they share (docs/adr/0007-django.md)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request

from agentgov.api import reach
from agentgov.api.auth import Principal
from agentgov.registry import agents, instructions
from agentgov.web.instructions import classifier

router = APIRouter(prefix="/v1", tags=["instructions"])
# Administrators, for every team or for their teams' agents.
team_admin = reach.require("admin")


@router.get("/agents/{ref}/instructions")
def get_instructions(
    request: Request, ref: str, principal: Principal = Depends(reach.read)
) -> dict[str, Any]:
    """The agent's instructions from each source, and what the rules and classifier found."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        agent = reach.agent(s, principal, ref)
        return {"classifier": classifier(rt), "sources": instructions.for_agent(s, agent.id)}


@router.put("/agents/{ref}/instructions")
def set_instructions(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(team_admin),
) -> dict[str, Any]:
    """Set the agent's registered instructions. They are checked straight away."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        agent = reach.agent(s, principal, ref, "admin")
        row = instructions.report(
            s,
            agent,
            source="registered",
            text=body.get("text"),
            actor=principal.actor,
            classify=rt.guardian is not None,
        )
        agents.refresh_risk(s, rt.settings, agent)
        return instructions.to_dict(row)


@router.delete("/agents/{ref}/instructions")
def clear_instructions(
    request: Request,
    ref: str,
    source: str = "registered",
    principal: Principal = Depends(team_admin),
) -> dict[str, Any]:
    """Forget the agent's instructions from one source (``registered`` by default)."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        agent = reach.agent(s, principal, ref, "admin")
        instructions.clear(s, agent, source=source, actor=principal.actor)
        agents.refresh_risk(s, rt.settings, agent)
        return {"agent": agent.name, "source": source, "cleared": True}


@router.post("/agents/{ref}/instructions/rescan")
def rescan_instructions(
    request: Request, ref: str, principal: Principal = Depends(team_admin)
) -> dict[str, Any]:
    """Check the stored instructions again with the current rules and classifier."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        agent = reach.agent(s, principal, ref, "admin")
        count = instructions.rescan(
            s, agent, actor=principal.actor, classify=rt.guardian is not None
        )
        agents.refresh_risk(s, rt.settings, agent)
        return {"agent": agent.name, "rescanned": count}
