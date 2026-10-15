"""Agent instructions (system prompts) and what scanning finds in them."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest
from ninja import Body

from agentgov.api import reach
from agentgov.api.auth import READ_ROLES
from agentgov.registry import agents, instructions
from agentgov.registry.errors import ValidationError
from agentgov.web.api import Router
from agentgov.web.auth import guard, require, runtime

router = Router(tags=["instructions"])
# Administrators, for every team or for their teams' agents.
team_admin = guard(reach.require("admin"))


def classifier(rt: Any) -> dict[str, Any]:
    g = rt.guardian
    return {
        "enabled": g is not None,
        "model": g.model if g else None,
        "criteria": g.criteria if g else [],
    }


@router.get("/v1/agents/{ref}/instructions", auth=guard(reach.read))
def get_instructions(request: HttpRequest, ref: str) -> dict[str, Any]:
    """The agent's instructions from each source, and what the rules and classifier found."""
    principal = request.auth
    rt = runtime(request)
    with rt.db.session() as s:
        agent = reach.agent(s, principal, ref)
        return {"classifier": classifier(rt), "sources": instructions.for_agent(s, agent.id)}


@router.put("/v1/agents/{ref}/instructions", auth=team_admin)
def set_instructions(
    request: HttpRequest, ref: str, body: dict[str, Any] = Body(...)
) -> dict[str, Any]:
    """Set the agent's registered instructions. They are checked straight away."""
    principal = request.auth
    rt = runtime(request)
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


@router.delete("/v1/agents/{ref}/instructions", auth=team_admin)
def clear_instructions(
    request: HttpRequest, ref: str, source: str = "registered"
) -> dict[str, Any]:
    """Forget the agent's instructions from one source (``registered`` by default)."""
    principal = request.auth
    rt = runtime(request)
    with rt.db.session() as s:
        agent = reach.agent(s, principal, ref, "admin")
        instructions.clear(s, agent, source=source, actor=principal.actor)
        agents.refresh_risk(s, rt.settings, agent)
        return {"agent": agent.name, "source": source, "cleared": True}


@router.post("/v1/agents/{ref}/instructions/rescan", auth=team_admin)
def rescan_instructions(request: HttpRequest, ref: str) -> dict[str, Any]:
    """Check the stored instructions again with the current rules and classifier."""
    principal = request.auth
    rt = runtime(request)
    with rt.db.session() as s:
        agent = reach.agent(s, principal, ref, "admin")
        count = instructions.rescan(
            s, agent, actor=principal.actor, classify=rt.guardian is not None
        )
        agents.refresh_risk(s, rt.settings, agent)
        return {"agent": agent.name, "rescanned": count}


@router.post("/v1/instructions/check", auth=require(*READ_ROLES, "registrar"))
def check_instructions(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Check instructions without storing them, for example in a CI pipeline.

    With the classifier configured this waits for its verdicts unless
    ``classifier`` is false."""
    rt = runtime(request)
    classify = body.get("classifier", True)
    if not isinstance(classify, bool):
        raise ValidationError("classifier must be true or false")
    result = instructions.check(body.get("text"), rt.guardian, classify=classify)
    return {**result, "classifier": {**classifier(rt), **result["classifier"]}}
