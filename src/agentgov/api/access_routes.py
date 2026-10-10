"""Who has access: people signed in through single sign-on, and their sessions."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.registry import access

router = APIRouter(prefix="/v1/access", tags=["access"])
read = require(*READ_ROLES)
admin = require("admin")


@router.get("")
def overview(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """Everyone who has signed in (or been refused) and the sessions open now."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        return {
            "sso_enabled": rt.settings.sso_enabled,
            "bootstrap_token": bool(rt.settings.admin_token),
            "people": access.people(s),
            "sessions": [access.session_to_dict(r) for r in access.live_sessions(s)],
        }


@router.delete("/sessions/{session_id}")
def end_session(
    request: Request, session_id: str, principal: Principal = Depends(admin)
) -> dict[str, int]:
    """End one session. The person signs in again, which re-reads their roles."""
    with request.app.state.rt.db.session() as s:
        return {"ended": access.end_session(s, session_id, actor=principal.actor)}


@router.post("/people/{subject:path}/sign-out")
def sign_out(
    request: Request, subject: str, principal: Principal = Depends(admin)
) -> dict[str, int]:
    """End every session of one person (by the identity provider's subject)."""
    with request.app.state.rt.db.session() as s:
        return {"ended": access.sign_out(s, subject, actor=principal.actor)}
