"""Authentication and role checks for the control plane API."""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import HTTPException, Request

from agentgov.registry import apikeys

READ_ROLES = ("admin", "approver", "auditor")


@dataclass(frozen=True)
class Principal:
    name: str
    role: str

    @property
    def actor(self) -> str:
        return f"{self.role}:{self.name}"

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def authenticate(request: Request) -> Principal | None:
    token = _bearer(request)
    if not token:
        return None
    rt = request.app.state.rt
    settings = rt.settings
    if settings.admin_token and hmac.compare_digest(token, settings.admin_token):
        return Principal("bootstrap", "admin")
    if settings.service_token and hmac.compare_digest(token, settings.service_token):
        return Principal("internal", "service")
    with rt.db.session() as session:
        key = apikeys.authenticate(session, token)
        if key is not None:
            return Principal(key.name, key.role)
    return None


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
        if principal.role not in allowed:
            raise HTTPException(status_code=403, detail=f"role {principal.role!r} may not do this")
        return principal

    return dependency
