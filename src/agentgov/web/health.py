"""Health, what this control plane offers, and who is calling."""

from __future__ import annotations

from functools import cache
from typing import Any

from django.http import HttpRequest, HttpResponse
from sqlalchemy import text

from agentgov import __version__
from agentgov.api.auth import describe
from agentgov.identity import chains
from agentgov.web.api import Router, json_response
from agentgov.web.auth import runtime, signed_in

router = Router()


@cache
def _delegation_keys(secret: str | None) -> chains.Keys | None:
    return chains.keys(secret)


@router.get("/healthz", tags=["health"])
def healthz(request: HttpRequest) -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["health"])
def readyz(request: HttpRequest) -> dict[str, Any]:
    with runtime(request).db.session() as s:
        s.execute(text("SELECT 1"))
    return {"status": "ready", "version": __version__}


@router.get("/v1/info", tags=["health"])
def info(request: HttpRequest) -> dict[str, Any]:
    settings = runtime(request).settings
    return {
        "version": __version__,
        "gateway_url": settings.gateway_public_url,
        "identity_provider": "keycloak" if settings.keycloak_enabled else None,
        "token_endpoint": (
            settings.keycloak_issuer.rstrip("/") + "/protocol/openid-connect/token"
            if settings.keycloak_issuer
            else None
        ),
        "audience": settings.gateway_audience,
        # What the tokens of the identity issuers the gateway trusts carry, unless an
        # issuer names an audience of its own.
        "issuer_audience": settings.gateway_public_url.rstrip("/"),
        "opa": bool(settings.opa_url),
        "sso": {"enabled": settings.sso_enabled, "login_url": "/auth/login"},
        # Signed-in administrators can act in Microsoft 365 through AgentGov.
        "microsoft_admin_actions": settings.microsoft_admin_actions,
        # IBM Granite Guardian, for agent instructions and traffic (docs/detection.md).
        "classifier": {
            "enabled": bool(settings.guardian_url),
            "model": settings.guardian_model if settings.guardian_url else None,
        },
        # Where agents find the keys to check the delegations AgentGov gives them.
        "delegation_jwks": (
            "/v1/delegations/jwks" if _delegation_keys(settings.key_secret) else None
        ),
        # The transparency log the ledger's checkpoints go into (docs/evidence.md).
        "transparency_log": settings.ledger_rekor_url,
    }


@router.get("/v1/delegations/jwks", tags=["health"])
def delegation_jwks(request: HttpRequest) -> HttpResponse:
    """The public keys of the delegations AgentGov gives the agents it calls through the
    gateway: an agent that checks the one each call carries refuses calls around the
    gateway (docs/agent-to-agent.md#calls-around-the-gateway). No secret."""
    keys = _delegation_keys(runtime(request).settings.key_secret)
    return json_response(chains.jwks(keys), headers={"Cache-Control": "public, max-age=300"})


@router.get("/v1/me", tags=["system"], auth=signed_in)
def whoami(request: HttpRequest) -> dict[str, Any]:
    """The caller's identity and roles, so clients can tailor what they offer."""
    return describe(runtime(request), request.auth)
