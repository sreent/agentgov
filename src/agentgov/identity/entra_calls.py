"""Checking the tokens Microsoft services send when they call AgentGov.

Copilot Studio's threat detection calls AgentGov with an access token from
Microsoft Entra ID, issued to an app registration in the organisation's tenant
(the one connected to Copilot Studio) for AgentGov's API, whose application ID
URI is AgentGov's address. AgentGov accepts a token only when Entra signed it,
for this tenant, for AgentGov, and for one of the calling apps it was told about.

Entra issues v1.0 or v2.0 tokens depending on the API's app registration
(``accessTokenAcceptedVersion``), so both are accepted: v1.0 tokens name the
calling app in ``appid`` and the tenant in ``https://sts.windows.net/<tenant>/``;
v2.0 tokens in ``azp`` and ``https://login.microsoftonline.com/<tenant>/v2.0``.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx
import jwt

# Asymmetric algorithms only, as for sign-in tokens.
ALGORITHMS = ["RS256"]
KEYS_REFETCH_SECONDS = 300


class CallerRejected(Exception):
    """The call's token is missing or not acceptable; the message says why."""


class EntraCallers:
    def __init__(
        self,
        *,
        tenant_id: str,
        audiences: list[str],
        app_ids: list[str],
        login_url: str = "https://login.microsoftonline.com",
        http: httpx.Client | None = None,
    ) -> None:
        self.tenant_id = tenant_id.lower()
        self.audiences = [a for a in audiences if a]
        self.app_ids = {a.lower() for a in app_ids if a}
        self.issuers = {
            f"{login_url.rstrip('/')}/{self.tenant_id}/v2.0",
            f"https://sts.windows.net/{self.tenant_id}/",
        }
        self.jwks_url = f"{login_url.rstrip('/')}/{self.tenant_id}/discovery/v2.0/keys"
        self._http = http or httpx.Client(timeout=5)
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at = 0.0
        self._lock = threading.Lock()

    def _key(self, token: str) -> jwt.PyJWK:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
            raise CallerRejected(f"malformed token: {exc}") from exc
        with self._lock:
            stale = time.monotonic() - self._fetched_at > KEYS_REFETCH_SECONDS
            if kid not in self._keys and (stale or not self._keys):
                self._refresh()
            key = self._keys.get(kid)
        if key is None:
            raise CallerRejected(f"token signed with an unknown key {kid!r}")
        return key

    def _refresh(self) -> None:
        try:
            resp = self._http.get(self.jwks_url)
            resp.raise_for_status()
            keys = resp.json().get("keys", [])
        except (httpx.HTTPError, ValueError) as exc:
            raise CallerRejected(f"cannot fetch Microsoft Entra ID's signing keys: {exc}") from exc
        found = {}
        for data in keys:
            if data.get("use", "sig") != "sig":
                continue
            try:
                found[data.get("kid")] = jwt.PyJWK.from_dict(data, algorithm="RS256")
            except jwt.PyJWTError:
                continue
        self._keys, self._fetched_at = found, time.monotonic()

    def check(self, authorization: str | None) -> dict[str, Any]:
        """The token's claims, if Microsoft may make this call; raises CallerRejected."""
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise CallerRejected("no bearer token")
        token = token.strip()
        key = self._key(token)
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=ALGORITHMS,
                audience=self.audiences,
                options={"require": ["exp", "iss", "aud"], "verify_iss": False},
                leeway=60,
            )
        except jwt.PyJWTError as exc:
            raise CallerRejected(f"token rejected: {exc}") from exc
        if claims.get("iss") not in self.issuers:
            raise CallerRejected(f"token issued by {claims.get('iss')!r}, not this tenant")
        if str(claims.get("tid", "")).lower() != self.tenant_id:
            raise CallerRejected("token issued for another tenant")
        caller = str(claims.get("azp") or claims.get("appid") or "").lower()
        if caller not in self.app_ids:
            raise CallerRejected(f"app {caller or '(none)'} may not call AgentGov")
        return claims
