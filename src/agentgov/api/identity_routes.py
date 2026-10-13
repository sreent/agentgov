"""Identity issuers: where agents' own identities come from, so they need no client secret."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from sqlalchemy import func, select

from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.api.versions import if_match
from agentgov.models import Agent
from agentgov.registry import features, identity_issuers
from agentgov.registry.errors import Conflict, NotFound
from agentgov.secops import handoff

router = APIRouter(prefix="/v1/identity-issuers", tags=["identity"])
read = require(*READ_ROLES)
admin = require("admin")
# Agents' own identities: off, no issuer is trusted, in Keycloak or at the gateway.
OWN_IDENTITIES = "workload-identity"


def _with_count(s: Any, issuer: Any) -> dict[str, Any]:
    return identity_issuers.to_dict(
        issuer, identity_issuers.agent_count(s, issuer), on=features.is_on(s, OWN_IDENTITIES)
    )


def _not_keycloak(request: Request, issuer: Any) -> None:
    """The gateway takes Keycloak's tokens as AgentGov's own: not as another issuer's too."""
    own = request.app.state.rt.settings.keycloak_issuer
    if issuer.gateway and own and issuer.issuer.rstrip("/") == own.rstrip("/"):
        raise Conflict(
            f"{issuer.issuer} is AgentGov's own Keycloak, whose tokens the gateway takes already"
        )


def _keys_now(request: Request, name: str, trusted: bool) -> dict[str, Any]:
    """The issuer, its keys fetched first when the gateway is to take its tokens: whether
    it can is known at once (docs/agent-identity.md#straight-to-the-gateway)."""
    rt = request.app.state.rt
    if trusted:
        rt.refresh_issuer_keys([name])
    with rt.db.session() as s:
        return _with_count(s, identity_issuers.get(s, name))


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
        on = features.is_on(s, OWN_IDENTITIES)
        return [
            identity_issuers.to_dict(i, counts.get(i.name, 0), on=on)
            for i in identity_issuers.list_all(s)
        ]


@router.post("", status_code=201)
def create_issuer(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Trust an identity issuer: agents can then authenticate with its tokens (with
    ``gateway``, at the gateway too)."""
    with request.app.state.rt.db.session() as s:
        issuer = identity_issuers.create(s, body, actor=principal.actor)
        _not_keycloak(request, issuer)
        name, trusted = issuer.name, issuer.gateway
    return _keys_now(request, name, trusted)


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
        changed = identity_issuers.update(
            s, issuer, body, actor=principal.actor, version=if_match(request)
        )
        _not_keycloak(request, issuer)
        name = issuer.name
        # Where its keys are may have changed, or the gateway is to take its tokens now.
        fetch = issuer.gateway and bool({"gateway", "issuer", "keys_url"} & set(changed))
    return _keys_now(request, name, fetch)


@router.post("/{ref}/keys")
def fetch_issuer_keys(request: Request, ref: str, _: Principal = Depends(admin)) -> dict[str, Any]:
    """Fetch the signing keys of an issuer the gateway trusts now, as when it rotated them
    sooner than AgentGov fetches them again (AGENTGOV_ISSUER_KEYS_INTERVAL_SECONDS)."""
    with request.app.state.rt.db.session() as s:
        issuer = identity_issuers.get(s, ref)
        if not issuer.gateway:
            raise Conflict(f"the gateway doesn't take {issuer.name}'s tokens: it has no keys there")
        name = issuer.name
    return _keys_now(request, name, True)


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
