"""Identity issuers: where agents' own identities come from, so they need no client secret."""

from __future__ import annotations

from typing import Any

from django.db.models import Count
from django.http import HttpRequest
from ninja import Body

from agentgov.api.auth import READ_ROLES
from agentgov.api.versions import if_match
from agentgov.db.models import Agent
from agentgov.registry import features, identity_issuers
from agentgov.registry.errors import Conflict, NotFound
from agentgov.secops import handoff
from agentgov.web.api import Router
from agentgov.web.auth import require, runtime

router = Router(tags=["identity"])
read = require(*READ_ROLES)
admin = require("admin")
# Agents' own identities: off, no issuer is trusted, in Keycloak or at the gateway.
OWN_IDENTITIES = "workload-identity"


def _with_count(s: Any, issuer: Any) -> dict[str, Any]:
    return identity_issuers.to_dict(
        issuer, identity_issuers.agent_count(s, issuer), on=features.is_on(s, OWN_IDENTITIES)
    )


def _not_keycloak(rt: Any, issuer: Any) -> None:
    """The gateway takes Keycloak's tokens as AgentGov's own: not as another issuer's too."""
    own = rt.settings.keycloak_issuer
    if issuer.gateway and own and issuer.issuer.rstrip("/") == own.rstrip("/"):
        raise Conflict(
            f"{issuer.issuer} is AgentGov's own Keycloak, whose tokens the gateway takes already"
        )


def _keys_now(rt: Any, name: str, trusted: bool) -> dict[str, Any]:
    """The issuer, its keys fetched first when the gateway is to take its tokens: whether
    it can is known at once (docs/agent-identity.md#straight-to-the-gateway)."""
    if trusted:
        rt.refresh_issuer_keys([name])
    with rt.db.transaction() as tx:
        return _with_count(tx, identity_issuers.get(tx, name))


@router.get("/v1/identity-issuers", auth=read)
def list_issuers(request: HttpRequest) -> list[dict[str, Any]]:
    with runtime(request).db.transaction() as tx:
        counts = dict(
            Agent.objects.filter(workload_issuer__isnull=False)
            .values("workload_issuer")
            .annotate(n=Count("id"))
            .order_by()
            .values_list("workload_issuer", "n")
        )
        on = features.is_on(tx, OWN_IDENTITIES)
        return [
            identity_issuers.to_dict(i, counts.get(i.name, 0), on=on)
            for i in identity_issuers.list_all(tx)
        ]


@router.post("/v1/identity-issuers", status_code=201, auth=admin)
def create_issuer(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Trust an identity issuer: agents can then authenticate with its tokens (with
    ``gateway``, at the gateway too)."""
    rt = runtime(request)
    with rt.db.transaction() as tx:
        issuer = identity_issuers.create(tx, body, actor=request.auth.actor)
        _not_keycloak(rt, issuer)
        name, trusted = issuer.name, issuer.gateway
    return _keys_now(rt, name, trusted)


@router.get("/v1/identity-issuers/{ref}", auth=read)
def get_issuer(request: HttpRequest, ref: str) -> dict[str, Any]:
    with runtime(request).db.transaction() as tx:
        return _with_count(tx, identity_issuers.get(tx, ref))


@router.patch("/v1/identity-issuers/{ref}", auth=admin)
def update_issuer(
    request: HttpRequest, ref: str, body: dict[str, Any] = Body(...)
) -> dict[str, Any]:
    rt = runtime(request)
    with rt.db.transaction() as tx:
        issuer = identity_issuers.get(tx, ref)
        changed = identity_issuers.update(
            tx, issuer, body, actor=request.auth.actor, version=if_match(request)
        )
        _not_keycloak(rt, issuer)
        name = issuer.name
        # Where its keys are may have changed, or the gateway is to take its tokens now.
        fetch = issuer.gateway and bool({"gateway", "issuer", "keys_url"} & set(changed))
    return _keys_now(rt, name, fetch)


@router.post("/v1/identity-issuers/{ref}/keys", auth=admin)
def fetch_issuer_keys(request: HttpRequest, ref: str) -> dict[str, Any]:
    """Fetch the signing keys of an issuer the gateway trusts now, as when it rotated them
    sooner than AgentGov fetches them again (AGENTGOV_ISSUER_KEYS_INTERVAL_SECONDS)."""
    rt = runtime(request)
    with rt.db.transaction() as tx:
        issuer = identity_issuers.get(tx, ref)
        if not issuer.gateway:
            raise Conflict(f"the gateway doesn't take {issuer.name}'s tokens: it has no keys there")
        name = issuer.name
    return _keys_now(rt, name, True)


@router.post("/v1/identity-issuers/{ref}/{action}", auth=require("secops"))
def issuer_action(request: HttpRequest, ref: str, action: str) -> dict[str, Any]:
    """``block`` stops every agent authenticating with the issuer's tokens; ``unblock``
    lets them again."""
    if action not in ("block", "unblock"):
        raise NotFound(f"no action {action!r}: block or unblock")
    principal = request.auth
    with runtime(request).db.transaction() as tx:
        handoff.check_kill_switch(tx, principal, action)
        issuer = identity_issuers.get(tx, ref)
        identity_issuers.set_status(tx, issuer, action, actor=principal.actor)
        return _with_count(tx, issuer)


@router.delete("/v1/identity-issuers/{ref}", status_code=204, auth=admin)
def delete_issuer(request: HttpRequest, ref: str) -> None:
    with runtime(request).db.transaction() as tx:
        identity_issuers.delete(tx, identity_issuers.get(tx, ref), actor=request.auth.actor)
