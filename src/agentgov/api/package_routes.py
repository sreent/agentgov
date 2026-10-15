"""The access packages an agent holds (docs/access-packages.md). The packages and their
assignments are on Django (agentgov.web.packages); this route moves there with the registry's
agent routes, whose paths it shares (docs/adr/0007-django.md)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from agentgov.api.auth import Principal, require, signed_in
from agentgov.registry import access_packages, agents
from agentgov.web.packages import _may_read

router = APIRouter(prefix="/v1", tags=["access packages"])
admin = require("admin")


def _rt(request: Request) -> Any:
    return request.app.state.rt


@router.get("/agents/{ref}/access-packages", tags=["agents"])
def agent_packages(
    request: Request, ref: str, principal: Principal = Depends(signed_in)
) -> list[dict[str, Any]]:
    """The access packages an agent holds and has asked for, newest first."""
    with _rt(request).db.session() as s:
        agent = agents.get(s, ref)
        _may_read(s, principal, agent, f"agent {ref!r} not found")
        return [
            access_packages.assignment_dict(s, r)
            for r in access_packages.assignments(s, agent_id=agent.id)
        ]
