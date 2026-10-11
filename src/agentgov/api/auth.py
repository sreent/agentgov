"""Authentication and role checks for the control plane API.

Callers authenticate with a bearer token (the bootstrap admin token, the
internal service token, an API key, or the session token ``agentgov login``
gets) or, for people signed in through single sign-on in a browser, with the
session cookie set by ``/auth/callback``.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request

from agentgov.identity import sso
from agentgov.registry import apikeys, features

READ_ROLES = ("admin", "approver", "auditor")
SESSION_COOKIE = "agentgov_session"
# Cookie-authenticated writes must carry this header. Browsers do not let other
# sites add custom headers to cross-origin requests (no CORS is enabled), so
# it blocks cross-site request forgery.
CSRF_HEADER = "x-agentgov-csrf"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    # Every role held; ``role`` is the most privileged one (people signed in
    # through single sign-on can hold several).
    roles: frozenset[str] = frozenset()
    # "token" (bootstrap/service), "api_key" or "session" (single sign-on).
    via: str = "token"
    # For single sign-on: the session, and whether AgentGov holds a Microsoft
    # sign-in for it (to act as this person in Microsoft 365 and Power Platform).
    session_id: str | None = None
    microsoft: bool = False
    # For single sign-on: who signed in, as the provider names them (the token's subject).
    subject: str | None = None

    def __post_init__(self) -> None:
        if not self.roles:
            object.__setattr__(self, "roles", frozenset({self.role}))

    @property
    def actor(self) -> str:
        return f"{self.role}:{self.name}"

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "roles": sorted(self.roles),
            "actor": self.actor,
            "via": self.via,
            "microsoft": self.microsoft,
        }


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def authenticate(request: Request) -> Principal | None:
    rt = request.app.state.rt
    settings = rt.settings
    token = bearer_token(request)
    if token:
        if settings.admin_token and hmac.compare_digest(token, settings.admin_token):
            return Principal("bootstrap", "admin")
        if settings.service_token and hmac.compare_digest(token, settings.service_token):
            return Principal("internal", "service")
        with rt.db.session() as session:
            key = apikeys.authenticate(session, token)
            if key is not None:
                return Principal(key.name, key.role, via="api_key")
        # A session token from `agentgov login`. Browsers never send these by
        # themselves, so they need no CSRF header.
        return _signed_in(rt, token)
    if not request.cookies.get(SESSION_COOKIE) or not settings.sso_enabled:
        return None
    if request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != "1":
        raise HTTPException(403, "cross-site request refused: send the X-AgentGov-CSRF header")
    return session_principal(request)


def session_principal(request: Request) -> Principal | None:
    """The person signed in through single sign-on, from the session cookie."""
    return _signed_in(request.app.state.rt, request.cookies.get(SESSION_COOKIE))


def _signed_in(rt: Any, token: str | None) -> Principal | None:
    if not token or not rt.settings.sso_enabled:
        return None
    with rt.db.session() as session:
        record = sso.lookup(session, token)
        if record is None:
            return None
        roles = [r for r in sso.SSO_ROLES if r in (record.roles or [])]
        if not roles:
            # Someone without an AgentGov role, there to decide the requests sent to them.
            if sso.PERSON not in (record.roles or []):
                return None
            if not features.is_on(session, "approvals-by-person"):
                return None
            roles = [sso.PERSON]
        delegations = getattr(rt, "delegations", None)
        return Principal(
            record.name,
            roles[0],
            frozenset(roles),
            via="session",
            session_id=record.id,
            microsoft=delegations is not None and delegations.has(record.id),
            subject=record.subject,
        )


def signed_in(request: Request) -> Principal:
    """Anyone authenticated, whatever their role."""
    principal = authenticate(request)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="missing or invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def require(*roles: str) -> Callable[[Request], Principal]:
    allowed = set(roles) | {"admin"}

    def dependency(request: Request) -> Principal:
        principal = authenticate(request)
        if principal is None:
            raise HTTPException(
                status_code=401,
                detail="missing or invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not principal.roles & allowed:
            raise HTTPException(status_code=403, detail=f"role {principal.role!r} may not do this")
        return principal

    return dependency
