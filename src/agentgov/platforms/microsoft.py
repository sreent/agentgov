"""Microsoft 365's agent catalog, read with Microsoft Graph.

Uses the Package Management API (``GET /v1.0/copilot/admin/catalog/packages``)
with an app-only token: an Entra app registration holding the application
permission ``CopilotPackages.Read.All``. Microsoft requires a Microsoft Agent
365 licence for this API. Blocking a package needs a signed-in admin
(delegated only), so AgentGov reads the catalog but does not change it.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from agentgov.config import Settings

# Agents are the packages Microsoft 365 Copilot can host.
AGENTS_FILTER = "supportedHosts/any(h:h eq 'Copilot')"
MAX_PAGES = 200


class PlatformError(Exception):
    """A platform could not be read; the message says why."""


class Microsoft365Catalog:
    def __init__(self, settings: Settings, *, http: httpx.Client | None = None) -> None:
        self.settings = settings
        self._http = http or httpx.Client(timeout=30)
        self._token: str | None = None
        self._token_expires = 0.0

    def _access_token(self) -> str:
        if self._token and time.monotonic() < self._token_expires:
            return self._token
        s = self.settings
        url = f"{s.entra_login_url.rstrip('/')}/{s.m365_tenant_id}/oauth2/v2.0/token"
        try:
            resp = self._http.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": s.m365_client_id,
                    "client_secret": s.m365_client_secret,
                    "scope": f"{s.graph_url.rstrip('/')}/.default",
                },
            )
        except httpx.HTTPError as exc:
            raise PlatformError(f"Microsoft Entra ID is unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise PlatformError(f"Microsoft Entra ID refused the app's credentials: {_error(resp)}")
        body = resp.json()
        self._token = body["access_token"]
        self._token_expires = time.monotonic() + max(int(body.get("expires_in", 3600)) - 120, 60)
        return self._token

    def agents(self) -> list[dict[str, Any]]:
        """Every agent in the organisation's catalog (all pages)."""
        url: str | None = (
            f"{self.settings.graph_url.rstrip('/')}/v1.0/copilot/admin/catalog/packages"
        )
        params: dict[str, str] | None = {"$filter": AGENTS_FILTER}
        found: list[dict[str, Any]] = []
        for _ in range(MAX_PAGES):
            if url is None:
                return found
            try:
                resp = self._http.get(
                    url,
                    params=params,
                    headers={"Authorization": f"Bearer {self._access_token()}"},
                )
            except httpx.HTTPError as exc:
                raise PlatformError(f"Microsoft Graph is unreachable: {exc}") from exc
            if resp.status_code != 200:
                hint = (
                    " (the app needs CopilotPackages.Read.All with admin consent, and the "
                    "tenant a Microsoft Agent 365 licence)"
                    if resp.status_code in (401, 403)
                    else ""
                )
                raise PlatformError(f"Microsoft Graph answered {_error(resp)}{hint}")
            body = resp.json()
            found.extend(item for item in body.get("value", []) if isinstance(item, dict))
            # Paging is server-driven: follow the opaque next link exactly as given.
            url, params = body.get("@odata.nextLink"), None
        raise PlatformError(f"stopped after {MAX_PAGES} pages of the agent catalog")


def _error(resp: httpx.Response) -> str:
    """Graph errors are {"error": {"message": ...}}; Entra's are {"error": "...", ...}."""
    detail = None
    try:
        body = resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        error = body.get("error")
        detail = error.get("message") if isinstance(error, dict) else None
        detail = (
            detail or body.get("error_description") or (error if isinstance(error, str) else None)
        )
    return f"{resp.status_code}: {detail or resp.text[:200]}"
