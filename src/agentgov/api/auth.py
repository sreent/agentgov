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
from agentgov.secops import handoff
from agentgov.tls import INTERNAL

READ_ROLES = ("admin", "approver", "secops", "auditor")
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

    @property
    def teams(self) -> dict[str, frozenset[str]]:
        """The roles held for some teams only (approver@sales), and those teams. They never
        count where a role is checked for itself: only where its team is checked too
        (agentgov.api.reach)."""
        held: dict[str, set[str]] = {}
        for value in self.roles:
            role, team = sso.split_role(value)
            if team is not None and role in sso.TEAM_ROLES:
                held.setdefault(role, set()).add(team)
        return {role: frozenset(names) for role, names in held.items()}

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "roles": sorted(self.roles),
            "teams": {role: sorted(names) for role, names in sorted(self.teams.items())},
            "actor": self.actor,
            "via": self.via,
            "microsoft": self.microsoft,
        }


def describe(rt: Any, principal: Principal) -> dict[str, Any]:
    """Who is signed in and with which roles; what is sent to people themselves (issues,
    and approval requests); and, for the secops role, what the hand-off lets it do."""
    out = principal.describe()
    with rt.db.session() as s:
        out["inbox"] = {
            "issues": features.is_on(s, "issues"),
            "approvals": features.is_on(s, "approvals-by-person"),
        }
        if "secops" in principal.roles or "secops" in principal.teams:
            out["handoff"] = {"level": handoff.level(s), "reached": handoff.reached(s)}
    return out


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def authenticate(request: Request) -> Principal | None:
    principal = _principal(request)
    settings = request.app.state.rt.settings
    # With mutual TLS the service role is the internal port's alone, however a caller
    # came by it (the service token or an API key with the role).
    service = principal is not None and principal.role == "service"
    if service and settings.tls_dir and not _internal(request):
        raise HTTPException(
            403,
            "with mutual TLS, components call the control plane on its internal "
            f"port ({settings.internal_port}), with their certificate",
        )
    return principal


def _internal(request: Request) -> bool:
    """Whether the request came in on the internal listener, where every caller showed a
    certificate from AgentGov's authority (mutual TLS, agentgov.tls)."""
    return bool((request.scope.get("state") or {}).get(INTERNAL))


def _principal(request: Request) -> Principal | None:
    rt = request.app.state.rt
    settings = rt.settings
    token = bearer_token(request)
    internal = _internal(request)
    if token:
        if settings.admin_token and hmac.compare_digest(token, settings.admin_token):
            return Principal("bootstrap", "admin")
        if settings.service_token and hmac.compare_digest(token, settings.service_token):
            return Principal("internal", "service")
        try:
            with rt.db.session() as session:
                key = apikeys.authenticate(session, token, max_days=settings.api_key_max_days)
                if key is not None:
                    return Principal(key.name, key.role, via="api_key")
        except apikeys.Expired as exc:
            raise HTTPException(
                401,
                f"{exc}: an administrator creates a new key (Access, or agentgov apikeys create)",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            ) from exc
        # A session token from `agentgov login`. Browsers never send these by
        # themselves, so they need no CSRF header.
        return _signed_in(rt, token)
    if internal:
        # A component that shows its certificate needs no token (OPA can't send both).
        return Principal("internal", "service")
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
        # For every team, then for one (approver@sales).
        roles = [r for r in sso.ordered(record.roles or []) if r != sso.PERSON]
        if not roles:
            # Someone without an AgentGov role, there for the requests and issues sent to
            # them: given the person role, or, while anyone may sign in, with none at all.
            if not sso.people_may_sign_in(session):
                return None
            if sso.PERSON not in (record.roles or []) and rt.settings.oidc_require_role:
                return None
            roles = [sso.PERSON]
        delegations = getattr(rt, "delegations", None)
        return Principal(
            record.name,
            roles[0],
            frozenset(roles),
            via="session",
            session_id=record.id,
            microsoft=delegations is not None and delegations.has(record.id, session=session),
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
