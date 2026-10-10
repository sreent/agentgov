"""Microsoft 365's agent catalog, read with Microsoft Graph.

Uses the Package Management API (``GET /v1.0/copilot/admin/catalog/packages``)
with an app-only token: an Entra app registration holding the application
permission ``CopilotPackages.Read.All``. Microsoft requires a Microsoft Agent
365 licence for this API. Blocking a package needs a signed-in admin
(delegated only), so AgentGov reads the catalog but does not change it.

A package's details include its elements' definitions; for a declarative agent
that is its manifest, which holds the agent's instructions.
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import quote

import httpx

from agentgov.config import Settings

# Agents are the packages Microsoft 365 Copilot can host.
AGENTS_FILTER = "supportedHosts/any(h:h eq 'Copilot')"
MAX_PAGES = 200
DECLARATIVE_AGENT = "declarativeagent"


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

    @property
    def _packages_url(self) -> str:
        return f"{self.settings.graph_url.rstrip('/')}/v1.0/copilot/admin/catalog/packages"

    def _get(self, url: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        try:
            resp = self._http.get(
                url, params=params, headers={"Authorization": f"Bearer {self._access_token()}"}
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
        if not isinstance(body, dict):
            raise PlatformError("Microsoft Graph answered with something other than an object")
        return body

    def agents(self) -> list[dict[str, Any]]:
        """Every agent in the organisation's catalog (all pages)."""
        url: str | None = self._packages_url
        params: dict[str, str] | None = {"$filter": AGENTS_FILTER}
        found: list[dict[str, Any]] = []
        for _ in range(MAX_PAGES):
            if url is None:
                return found
            body = self._get(url, params)
            found.extend(item for item in body.get("value", []) if isinstance(item, dict))
            # Paging is server-driven: follow the opaque next link exactly as given.
            url, params = body.get("@odata.nextLink"), None
        raise PlatformError(f"stopped after {MAX_PAGES} pages of the agent catalog")

    def package(self, package_id: str) -> dict[str, Any]:
        """One package's details, with its elements' definitions."""
        return self._get(f"{self._packages_url}/{quote(package_id, safe='')}")


def is_declarative(package: dict[str, Any]) -> bool:
    return any(str(t).lower() == DECLARATIVE_AGENT for t in package.get("elementTypes") or [])


def declarative_instructions(detail: dict[str, Any]) -> str | None:
    """The instructions in a package's declarative agent manifests, when Graph includes them."""
    texts = []
    for group in detail.get("elementDetails") or []:
        if not isinstance(group, dict) or str(group.get("elementType", "")).lower() != (
            DECLARATIVE_AGENT
        ):
            continue
        for element in group.get("elements") or []:
            definition = element.get("definition") if isinstance(element, dict) else None
            if isinstance(definition, str):
                try:
                    definition = json.loads(definition)
                except ValueError:
                    continue
            if isinstance(definition, dict) and isinstance(definition.get("instructions"), str):
                texts.append(definition["instructions"].strip())
    return "\n\n".join(t for t in texts if t) or None


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
