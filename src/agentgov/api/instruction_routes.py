"""Agent instructions (system prompts) and what scanning finds in them."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request

from agentgov.api import reach
from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.registry import agents, instructions
from agentgov.registry.errors import ValidationError

router = APIRouter(prefix="/v1", tags=["instructions"])
# Administrators, for every team or for their teams' agents.
team_admin = reach.require("admin")


def _classifier(rt: Any) -> dict[str, Any]:
    g = rt.guardian
    return {
        "enabled": g is not None,
        "model": g.model if g else None,
        "criteria": g.criteria if g else [],
    }


@router.get("/agents/{ref}/instructions")
def get_instructions(
    request: Request, ref: str, principal: Principal = Depends(reach.read)
) -> dict[str, Any]:
    """The agent's instructions from each source, and what the rules and classifier found."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        agent = reach.agent(s, principal, ref)
        return {"classifier": _classifier(rt), "sources": instructions.for_agent(s, agent.id)}


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


@router.post("/instructions/check")
def check_instructions(
    request: Request,
    body: dict[str, Any] = Body(...),
    _: Principal = Depends(require(*READ_ROLES, "registrar")),
) -> dict[str, Any]:
    """Check instructions without storing them, for example in a CI pipeline.

    With the classifier configured this waits for its verdicts unless
    ``classifier`` is false."""
    rt = request.app.state.rt
    classify = body.get("classifier", True)
    if not isinstance(classify, bool):
        raise ValidationError("classifier must be true or false")
    result = instructions.check(body.get("text"), rt.guardian, classify=classify)
    return {**result, "classifier": {**_classifier(rt), **result["classifier"]}}
