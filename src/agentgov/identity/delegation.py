"""Acting as a signed-in administrator in Microsoft 365 and Power Platform.

Some of Microsoft's admin APIs accept only a signed-in administrator, not an
application: quarantining Copilot Studio agents, querying the Power Platform
inventory, blocking Microsoft 365 agents. When administrators sign in to
AgentGov through Microsoft Entra ID, the control plane keeps the refresh token
from their sign-in and uses it to get access tokens for those APIs, so it can
act as them while they are signed in.

The tokens are held in memory only, for as long as the AgentGov session lasts.
They are never written to the database or the ledger, and they are lost when
the control plane restarts (signing in again restores them). Entra refresh
tokens issued to a confidential client are also useless without the client's
secret.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

from agentgov import ids
from agentgov.config import Settings

POWER_PLATFORM = "power-platform"
GRAPH = "graph"


class DelegationError(Exception):
    """AgentGov cannot act as this administrator in Microsoft; the message says why."""


@dataclass
class _Grant:
    refresh_token: str
    expires_at: datetime  # the AgentGov session's expiry
    access: dict[str, tuple[str, float]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


class Delegations:
    def __init__(self, settings: Settings, *, http: httpx.Client | None = None) -> None:
        self.settings = settings
        self._http = http or httpx.Client(timeout=15)
        self._grants: dict[str, _Grant] = {}
        self._lock = threading.Lock()
        self.scopes = {
            POWER_PLATFORM: f"{settings.power_platform_url.rstrip('/')}/.default",
            GRAPH: f"{settings.graph_url.rstrip('/')}/.default",
        }

    def remember(self, session_id: str, refresh_token: str, expires_at: datetime) -> None:
        with self._lock:
            self._purge()
            self._grants[session_id] = _Grant(refresh_token, expires_at)

    def move(self, key: str, session_id: str, expires_at: datetime) -> None:
        """Give the sign-in held under ``key`` (a CLI sign-in in flight) to a session."""
        with self._lock:
            grant = self._grants.pop(key, None)
            if grant is not None:
                grant.expires_at = expires_at
                self._grants[session_id] = grant

    def forget(self, *session_ids: str) -> None:
        with self._lock:
            for session_id in session_ids:
                self._grants.pop(session_id, None)

    def has(self, session_id: str | None) -> bool:
        grant = self._grants.get(session_id or "")
        return grant is not None and grant.expires_at > ids.utcnow()

    def _purge(self) -> None:
        now = ids.utcnow()
        for session_id in [s for s, g in self._grants.items() if g.expires_at <= now]:
            del self._grants[session_id]

    def access_token(self, session_id: str | None, api: str) -> str:
        """An access token for ``api`` (``power-platform`` or ``graph``) as this admin."""
        grant = self._grants.get(session_id or "")
        if grant is None or grant.expires_at <= ids.utcnow():
            raise DelegationError(
                "AgentGov holds no Microsoft sign-in for you: sign in again with Microsoft "
                "Entra ID (in the CLI, `agentgov login`). AgentGov keeps these sign-ins in "
                "memory only, so a restart of the control plane clears them"
            )
        with grant.lock:
            cached = grant.access.get(api)
            if cached and cached[1] > time.monotonic():
                return cached[0]
            body = self._refresh(grant.refresh_token, self.scopes[api])
            # Entra rotates refresh tokens: keep the newest.
            grant.refresh_token = body.get("refresh_token") or grant.refresh_token
            lifetime = max(int(body.get("expires_in", 3600)) - 120, 60)
            grant.access[api] = (body["access_token"], time.monotonic() + lifetime)
            return body["access_token"]

    def _refresh(self, refresh_token: str, scope: str) -> dict[str, Any]:
        s = self.settings
        try:
            resp = self._http.post(
                s.oidc_endpoints()["token_endpoint"],
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "scope": scope,
                },
                auth=(s.oidc_client_id, s.oidc_client_secret or ""),
            )
        except httpx.HTTPError as exc:
            raise DelegationError(f"Microsoft Entra ID is unreachable: {exc}") from exc
        if resp.status_code != 200:
            try:
                detail = resp.json().get("error_description") or resp.text
            except ValueError:
                detail = resp.text
            raise DelegationError(
                f"Microsoft Entra ID would not let AgentGov act as you: {str(detail)[:300]}"
            )
        body = resp.json()
        if "access_token" not in body:
            raise DelegationError("Microsoft Entra ID's answer had no access token")
        return body
