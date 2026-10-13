"""Who has access: people signed in through single sign-on, and their sessions."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.identity import sso
from agentgov.registry import access

router = APIRouter(prefix="/v1/access", tags=["access"])
read = require(*READ_ROLES)
admin = require("admin")


def provider(rt: Any) -> dict[str, Any] | None:
    """The identity provider people sign in with, and whether AgentGov can read it."""
    client = rt.sso
    if client is None:
        return None
    settings = rt.settings
    problem = None
    try:
        client.prepare()
    except sso.SSOError as exc:
        problem = str(exc)
    return {
        "kind": client.provider,
        "issuer": settings.oidc_issuer or settings.keycloak_issuer,
        "client_id": settings.oidc_client_id,
        "discovered": client.discovers,
        "roles_claims": client.roles_claims,
        "role_map": [
            {"value": value, "role": role}
            for value, roles in sorted(client.role_map.items())
            for role in sorted(roles)
        ],
        "role_prefix": None if client.role_map else settings.oidc_role_prefix,
        "allowed_domains": client.domains,
        # Only people with a role may sign in (AGENTGOV_OIDC_REQUIRE_ROLE).
        "require_role": settings.oidc_require_role,
        "problem": problem,
    }


@router.get("")
def overview(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """Everyone who has signed in (or been refused), the sessions open now, the roles
    given in AgentGov, and the identity provider."""
    rt = request.app.state.rt
    signing_in = provider(rt)  # may read the provider's discovery document
    with rt.db.session() as s:
        if signing_in is not None:
            # What someone gets who signs in with no role given to them: the person role,
            # or nothing (refused).
            signing_in["without_role"] = sso.without_role(s, rt.settings)
        return {
            "sso_enabled": rt.settings.sso_enabled,
            "bootstrap_token": bool(rt.settings.admin_token),
            "provider": signing_in,
            "people": access.people(s),
            "sessions": [access.session_to_dict(r) for r in access.live_sessions(s)],
            "grants": [access.grant_to_dict(g) for g in access.grants(s)],
            # How long new API keys work by default, and at most (0: no limit).
            "api_keys": {
                "default_days": rt.settings.api_key_days,
                "max_days": rt.settings.api_key_max_days,
            },
        }


class Grant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=255)
    role: str = Field(min_length=1, max_length=32)
    # For this team's agents only (docs/administration.md#roles-for-one-team).
    team: str | None = Field(None, max_length=128)
    reason: str | None = Field(None, max_length=1000)


@router.post("/grants", status_code=201)
def give_role(
    request: Request, body: Grant, principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Give a person an AgentGov role, by the email address their identity provider vouches
    for: from their next sign-in, beside the roles the provider gives them. With ``team``,
    for that team's agents only."""
    with request.app.state.rt.db.session() as s:
        record = access.grant(
            s, body.email, body.role, actor=principal.actor, reason=body.reason, team=body.team
        )
        return access.grant_to_dict(record)


@router.delete("/grants/{email}/{role}")
def take_role(
    request: Request, email: str, role: str, principal: Principal = Depends(admin)
) -> dict[str, int]:
    """Take away a role given in AgentGov; the person's sessions end with it."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        ended = access.revoke(s, email, role, actor=principal.actor)
    if rt.delegations is not None:
        rt.delegations.forget(*ended)
    return {"ended": len(ended)}


@router.delete("/sessions/{session_id}")
def end_session(
    request: Request, session_id: str, principal: Principal = Depends(admin)
) -> dict[str, int]:
    """End one session. The person signs in again, which re-reads their roles."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        ended = access.end_session(s, session_id, actor=principal.actor)
    if rt.delegations is not None:
        rt.delegations.forget(session_id)
    return {"ended": ended}


@router.post("/people/{subject:path}/sign-out")
def sign_out(
    request: Request, subject: str, principal: Principal = Depends(admin)
) -> dict[str, int]:
    """End every session of one person (by the identity provider's subject)."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        ended_ids = access.session_ids(s, subject)
        ended = access.sign_out(s, subject, actor=principal.actor)
    if rt.delegations is not None:
        rt.delegations.forget(*ended_ids)
    return {"ended": ended}
