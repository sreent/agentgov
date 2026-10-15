"""The management rules that match an agent (docs/management-rules.md). The rules
themselves are on Django (agentgov.web.rules); this route moves there with the registry's
agent routes, whose paths it shares (docs/adr/0007-django.md)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from agentgov.api import reach
from agentgov.api.auth import READ_ROLES, Principal, require, signed_in
from agentgov.registry import access_packages, agents, rules
from agentgov.registry.errors import NotFound

router = APIRouter(prefix="/v1", tags=["management rules"])
read = require(*READ_ROLES)
admin = require("admin")


def _rt(request: Request) -> Any:
    return request.app.state.rt


@router.get("/agents/{ref}/rules", tags=["agents"])
def agent_rules(
    request: Request, ref: str, principal: Principal = Depends(signed_in)
) -> list[dict[str, Any]]:
    """The rules that match the agent, and what each will do or did: for readers, and the
    agent's owner and sponsors."""
    with _rt(request).db.session() as s:
        agent = agents.get(s, ref)
        person = principal.person
        responsible = person is not None and person.lower() in access_packages.responsible(s, agent)
        if not reach.roles_at(s, principal, agent) & set(READ_ROLES) and not responsible:
            raise NotFound(f"agent {ref!r} not found")  # out of their reach
        return rules.for_agent(s, agent)
