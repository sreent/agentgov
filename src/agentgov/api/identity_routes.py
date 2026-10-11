"""Identity issuers: where agents' own identities come from, so they need no client secret."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from sqlalchemy import func, select

from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.models import Agent
from agentgov.registry import identity_issuers
from agentgov.registry.errors import NotFound
from agentgov.secops import handoff

router = APIRouter(prefix="/v1/identity-issuers", tags=["identity"])
read = require(*READ_ROLES)
admin = require("admin")


def _with_count(s: Any, issuer: Any) -> dict[str, Any]:
    return identity_issuers.to_dict(issuer, identity_issuers.agent_count(s, issuer))


@router.get("")
def list_issuers(request: Request, _: Principal = Depends(read)) -> list[dict[str, Any]]:
    with request.app.state.rt.db.session() as s:
        counts = dict(
            s.execute(
                select(Agent.workload_issuer, func.count())
                .where(Agent.workload_issuer.is_not(None))
                .group_by(Agent.workload_issuer)
            ).all()
        )
        return [
            identity_issuers.to_dict(i, counts.get(i.name, 0)) for i in identity_issuers.list_all(s)
        ]


@router.post("", status_code=201)
def create_issuer(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Trust an identity issuer: agents can then authenticate with its tokens."""
    with request.app.state.rt.db.session() as s:
        return _with_count(s, identity_issuers.create(s, body, actor=principal.actor))


@router.get("/{ref}")
def get_issuer(request: Request, ref: str, _: Principal = Depends(read)) -> dict[str, Any]:
    with request.app.state.rt.db.session() as s:
        return _with_count(s, identity_issuers.get(s, ref))


@router.patch("/{ref}")
def update_issuer(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    with request.app.state.rt.db.session() as s:
        issuer = identity_issuers.get(s, ref)
        identity_issuers.update(s, issuer, body, actor=principal.actor)
        return _with_count(s, issuer)


@router.post("/{ref}/{action}")
def issuer_action(
    request: Request, ref: str, action: str, principal: Principal = Depends(require("secops"))
) -> dict[str, Any]:
    """``block`` stops every agent authenticating with the issuer's tokens; ``unblock``
    lets them again."""
    if action not in ("block", "unblock"):
        raise NotFound(f"no action {action!r}: block or unblock")
    with request.app.state.rt.db.session() as s:
        handoff.check_kill_switch(s, principal, action)
        issuer = identity_issuers.get(s, ref)
        identity_issuers.set_status(s, issuer, action, actor=principal.actor)
        return _with_count(s, issuer)


@router.delete("/{ref}", status_code=204)
def delete_issuer(request: Request, ref: str, principal: Principal = Depends(admin)) -> None:
    with request.app.state.rt.db.session() as s:
        identity_issuers.delete(s, identity_issuers.get(s, ref), actor=principal.actor)
