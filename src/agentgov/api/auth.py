"""Authentication and role checks for the control plane API.

Callers authenticate with a bearer token (the bootstrap admin token, the
internal service token or an API key) or, for people signed in through single
sign-on, with the session cookie set by ``/auth/callback``.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request

from agentgov.identity import sso
from agentgov.registry import apikeys

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
        }


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def authenticate(request: Request) -> Principal | None:
    rt = request.app.state.rt
    settings = rt.settings
    token = _bearer(request)
    if token:
        if settings.admin_token and hmac.compare_digest(token, settings.admin_token):
            return Principal("bootstrap", "admin")
        if settings.service_token and hmac.compare_digest(token, settings.service_token):
            return Principal("internal", "service")
        with rt.db.session() as session:
            key = apikeys.authenticate(session, token)
            if key is not None:
                return Principal(key.name, key.role, via="api_key")
        return None
    if not request.cookies.get(SESSION_COOKIE) or not settings.sso_enabled:
        return None
    if request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != "1":
        raise HTTPException(403, "cross-site request refused: send the X-AgentGov-CSRF header")
    return session_principal(request)


def session_principal(request: Request) -> Principal | None:
    """The person signed in through single sign-on, from the session cookie."""
    rt = request.app.state.rt
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie or not rt.settings.sso_enabled:
        return None
    with rt.db.session() as session:
        record = sso.lookup(session, cookie)
        roles = [r for r in sso.SSO_ROLES if record is not None and r in (record.roles or [])]
        if not roles:
            return None
        return Principal(record.name, roles[0], frozenset(roles), via="session")


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
