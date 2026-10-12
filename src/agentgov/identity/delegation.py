"""Acting as a signed-in administrator in Microsoft 365 and Power Platform.

Some of Microsoft's admin APIs accept only a signed-in administrator, not an
application: quarantining Copilot Studio agents, querying the Power Platform
inventory, blocking Microsoft 365 agents. When administrators sign in to
AgentGov through Microsoft Entra ID, the control plane keeps the refresh token
from their sign-in and uses it to get access tokens for those APIs, so it can
act as them while they are signed in.

The refresh tokens are kept in the database, for as long as the AgentGov session
lasts, so that every control-plane replica can act as the administrator (and a
restart doesn't sign them out of Microsoft). Each is sealed (AES-256-GCM) with a
key derived from AgentGov's client secret, and bound to its session: the database
alone doesn't give them away, and they never reach the ledger. Entra refresh
tokens issued to a confidential client are useless without the client's secret
anyway. Rotating the secret makes the sealed tokens unreadable: administrators
sign in again. Access tokens stay in each replica's memory until they expire.
"""

from __future__ import annotations

import base64
import os
import threading
import time
from contextlib import nullcontext
from datetime import datetime
from typing import Any

import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import delete
from sqlalchemy.orm import Session

from agentgov import ids
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.models import MicrosoftGrant

POWER_PLATFORM = "power-platform"
GRAPH = "graph"
NONCE = 12
NO_SIGN_IN = (
    "AgentGov holds no Microsoft sign-in for you: sign in again with Microsoft Entra ID "
    "(in the CLI, `agentgov login`)"
)


class DelegationError(Exception):
    """AgentGov cannot act as this administrator in Microsoft; the message says why."""


def sealing_key(client_secret: str) -> bytes:
    """The key that seals refresh tokens, derived from AgentGov's client secret."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"agentgov microsoft sign-ins"
    ).derive(client_secret.encode())


class Delegations:
    def __init__(
        self, settings: Settings, db: Database, *, http: httpx.Client | None = None
    ) -> None:
        self.settings = settings
        self.db = db
        self._http = http or httpx.Client(timeout=15)
        self._key = AESGCM(sealing_key(settings.oidc_client_secret or ""))
        # Access tokens, per session and API: (token, expiry in monotonic seconds).
        self._access: dict[tuple[str, str], tuple[str, float]] = {}
        self._lock = threading.Lock()
        self.scopes = {
            POWER_PLATFORM: f"{settings.power_platform_url.rstrip('/')}/.default",
            GRAPH: f"{settings.graph_url.rstrip('/')}/.default",
        }

    # -- sealing ---------------------------------------------------------------------
    def _seal(self, session_id: str, refresh_token: str) -> str:
        nonce = os.urandom(NONCE)
        sealed = self._key.encrypt(nonce, refresh_token.encode(), session_id.encode())
        return base64.b64encode(nonce + sealed).decode()

    def _open(self, session_id: str, sealed: str) -> str | None:
        """The refresh token, or None if it can't be read (sealed under another secret)."""
        try:
            raw = base64.b64decode(sealed)
            return self._key.decrypt(raw[:NONCE], raw[NONCE:], session_id.encode()).decode()
        except (InvalidTag, ValueError):
            return None

    # -- grants ----------------------------------------------------------------------
    def remember(self, session_id: str, refresh_token: str, expires_at: datetime) -> None:
        with self.db.session() as s:
            now = ids.utcnow()
            s.execute(delete(MicrosoftGrant).where(MicrosoftGrant.expires_at <= now))
            row = s.get(MicrosoftGrant, session_id)
            if row is None:
                row = MicrosoftGrant(session_id=session_id)
                s.add(row)
            row.sealed = self._seal(session_id, refresh_token)
            row.expires_at, row.updated_at = expires_at, now
        self._forget_access(session_id)

    def move(self, key: str, session_id: str, expires_at: datetime) -> None:
        """Give the sign-in held under ``key`` (a CLI sign-in in flight) to a session."""
        with self.db.session() as s:
            row = s.get(MicrosoftGrant, key, with_for_update=True)
            if row is None:
                return
            token = self._open(key, row.sealed)
            s.delete(row)
            if token is not None:
                s.add(
                    MicrosoftGrant(
                        session_id=session_id,
                        sealed=self._seal(session_id, token),
                        expires_at=expires_at,
                        updated_at=ids.utcnow(),
                    )
                )
        self._forget_access(key)

    def forget(self, *session_ids: str) -> None:
        if not session_ids:
            return
        with self.db.session() as s:
            s.execute(delete(MicrosoftGrant).where(MicrosoftGrant.session_id.in_(session_ids)))
        self._forget_access(*session_ids)

    def _forget_access(self, *session_ids: str) -> None:
        with self._lock:
            for key in [k for k in self._access if k[0] in session_ids]:
                del self._access[key]

    def has(self, session_id: str | None, *, session: Session | None = None) -> bool:
        """Whether AgentGov can act as this session's administrator (in ``session``, a
        transaction the caller has open, if given)."""
        if not session_id:
            return False
        with nullcontext(session) if session is not None else self.db.session() as s:
            row = s.get(MicrosoftGrant, session_id)
            return row is not None and row.expires_at > ids.utcnow()

    def access_token(self, session_id: str | None, api: str) -> str:
        """An access token for ``api`` (``power-platform`` or ``graph``) as this admin."""
        with self.db.session() as s:
            # Locked while it is refreshed: two replicas don't spend the same refresh token.
            row = s.get(MicrosoftGrant, session_id or "", with_for_update=True)
            if row is None or row.expires_at <= ids.utcnow():
                raise DelegationError(NO_SIGN_IN)
            key = (row.session_id, api)
            with self._lock:
                cached = self._access.get(key)
            if cached and cached[1] > time.monotonic():
                return cached[0]
            token = self._open(row.session_id, row.sealed)
            if token is None:
                raise DelegationError(
                    "AgentGov can't read your Microsoft sign-in any more (its client secret "
                    "changed): sign in again with Microsoft Entra ID"
                )
            body = self._refresh(token, self.scopes[api])
            # Entra rotates refresh tokens: keep the newest.
            if body.get("refresh_token"):
                row.sealed = self._seal(row.session_id, body["refresh_token"])
                row.updated_at = ids.utcnow()
            lifetime = max(int(body.get("expires_in", 3600)) - 120, 60)
            with self._lock:
                self._access[key] = (body["access_token"], time.monotonic() + lifetime)
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
