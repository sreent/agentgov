"""Keycloak as the agent identity provider (the open Entra Agent ID).

Each registered agent gets its own confidential OAuth client in the AgentGov
realm, with a service account for the client-credentials grant. Two protocol
mappers put an ``agent_id`` claim and the gateway audience into every access
token, which agentgateway validates before any tool call reaches the
governance processor.

The reconciler is level-triggered: it compares each agent's lifecycle state
with its Keycloak client and converges them, so a missed notification or a
Keycloak outage only delays convergence.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any
from urllib.parse import quote

import httpx
from sqlalchemy import select

from agentgov import ids
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.models import ACTIVE, DISCOVERED, Agent

log = logging.getLogger(__name__)

TOKEN_LIFESPAN_SECONDS = 300


class KeycloakError(RuntimeError):
    pass


class KeycloakConflict(KeycloakError):
    """The resource already exists (HTTP 409)."""


class KeycloakAdmin:
    """Minimal Keycloak Admin REST client authenticated as a service account."""

    def __init__(
        self,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        *,
        http: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = http or httpx.Client(timeout=timeout)
        self._token: str | None = None
        self._token_expires = 0.0
        self._lock = threading.Lock()

    @property
    def admin_base(self) -> str:
        return f"{self.base_url}/admin/realms/{quote(self.realm)}"

    def _access_token(self, *, force: bool = False) -> str:
        with self._lock:
            if not force and self._token and time.monotonic() < self._token_expires:
                return self._token
            resp = self._http.post(
                f"{self.base_url}/realms/{quote(self.realm)}/protocol/openid-connect/token",
                data={"grant_type": "client_credentials"},
                auth=(self._client_id, self._client_secret),
            )
            if resp.status_code != 200:
                raise KeycloakError(f"token request failed: {resp.status_code} {resp.text[:200]}")
            body = resp.json()
            self._token = body["access_token"]
            self._token_expires = time.monotonic() + max(10, int(body.get("expires_in", 60)) - 30)
            return self._token

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        for attempt in (0, 1):
            headers = {"Authorization": f"Bearer {self._access_token(force=attempt == 1)}"}
            resp = self._http.request(method, f"{self.admin_base}{path}", headers=headers, **kwargs)
            if resp.status_code != 401:
                return resp
        return resp

    def _check(self, resp: httpx.Response, what: str) -> httpx.Response:
        if resp.status_code >= 400:
            raise KeycloakError(f"{what} failed: {resp.status_code} {resp.text[:300]}")
        return resp

    def find_client(self, client_id: str) -> dict[str, Any] | None:
        resp = self._check(
            self._request("GET", "/clients", params={"clientId": client_id}), "client lookup"
        )
        return next((c for c in resp.json() if c.get("clientId") == client_id), None)

    def create_client(self, representation: dict[str, Any]) -> str:
        resp = self._request("POST", "/clients", json=representation)
        if resp.status_code == 409:
            raise KeycloakConflict(f"client {representation['clientId']} already exists")
        self._check(resp, "client create")
        location = resp.headers.get("Location", "")
        if location:
            return location.rstrip("/").rsplit("/", 1)[-1]
        created = self.find_client(representation["clientId"])
        if created is None:
            raise KeycloakError("client created but could not be found")
        return created["id"]

    def update_client(self, uuid: str, representation: dict[str, Any]) -> None:
        self._check(self._request("PUT", f"/clients/{uuid}", json=representation), "client update")

    def delete_client(self, uuid: str) -> None:
        resp = self._request("DELETE", f"/clients/{uuid}")
        if resp.status_code not in (204, 404):
            self._check(resp, "client delete")

    def get_secret(self, uuid: str) -> str:
        resp = self._check(self._request("GET", f"/clients/{uuid}/client-secret"), "read secret")
        return resp.json()["value"]

    def regenerate_secret(self, uuid: str) -> str:
        resp = self._check(
            self._request("POST", f"/clients/{uuid}/client-secret"), "regenerate secret"
        )
        return resp.json()["value"]


def client_representation(agent: Agent, settings: Settings) -> dict[str, Any]:
    return {
        "clientId": agent.client_id,
        "name": f"{agent.name} (AgentGov agent)",
        "description": (agent.description or "")[:255],
        "enabled": agent.status == ACTIVE,
        "protocol": "openid-connect",
        "publicClient": False,
        "bearerOnly": False,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "frontchannelLogout": False,
        "clientAuthenticatorType": "client-secret",
        "attributes": {
            "agentgov.agent_id": agent.id,
            "agentgov.managed": "true",
            "access.token.lifespan": str(TOKEN_LIFESPAN_SECONDS),
            "client_credentials.use_refresh_token": "false",
        },
        "protocolMappers": [
            {
                "name": "agentgov-agent-id",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-hardcoded-claim-mapper",
                "consentRequired": False,
                "config": {
                    "claim.name": "agent_id",
                    "claim.value": agent.id,
                    "jsonType.label": "String",
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "userinfo.token.claim": "false",
                    "introspection.token.claim": "true",
                },
            },
            {
                "name": "agentgov-gateway-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.custom.audience": settings.gateway_audience,
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "introspection.token.claim": "true",
                },
            },
        ],
    }


class IdentityReconciler:
    def __init__(self, db: Database, settings: Settings, admin: KeycloakAdmin) -> None:
        self.db = db
        self.settings = settings
        self.admin = admin
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # The background worker and API requests may sync the same agent at once.
        self._sync_lock = threading.Lock()

    # -- convergence --------------------------------------------------------
    def sync(self, agent: Agent) -> None:
        """Converge one agent's Keycloak client with its lifecycle state."""
        if agent.status == DISCOVERED or not agent.client_id:
            return
        with self._sync_lock:
            self._sync(agent)

    def _sync(self, agent: Agent) -> None:
        existing = self.admin.find_client(agent.client_id or "")
        if existing is None:
            if agent.status != ACTIVE:
                # No credentials are minted until the agent is first approved.
                agent.identity_error = None
                return
            try:
                agent.idp_client_uuid = self.admin.create_client(
                    client_representation(agent, self.settings)
                )
                log.info("created Keycloak client %s for agent %s", agent.client_id, agent.name)
            except KeycloakConflict:
                existing = self.admin.find_client(agent.client_id or "")
                if existing is None:
                    raise
        if existing is not None:
            agent.idp_client_uuid = existing["id"]
            desired = client_representation(agent, self.settings)
            if (
                existing.get("enabled") != desired["enabled"]
                or existing.get("description", "") != desired["description"]
                or (existing.get("attributes") or {}).get("agentgov.agent_id") != agent.id
            ):
                merged = {
                    **existing,
                    **{k: v for k, v in desired.items() if k != "protocolMappers"},
                }
                merged["attributes"] = {
                    **(existing.get("attributes") or {}),
                    **desired["attributes"],
                }
                self.admin.update_client(existing["id"], merged)
                log.info(
                    "updated Keycloak client %s (enabled=%s)", agent.client_id, desired["enabled"]
                )
        agent.identity_synced_at = ids.utcnow()
        agent.identity_error = None

    def reconcile_all(self) -> dict[str, int]:
        synced = failed = 0
        with self.db.session() as session:
            for agent in session.scalars(select(Agent).where(Agent.status != DISCOVERED)).unique():
                try:
                    self.sync(agent)
                    synced += 1
                except (KeycloakError, httpx.HTTPError) as exc:
                    failed += 1
                    agent.identity_error = str(exc)[:500]
                    log.warning("identity sync failed for %s: %s", agent.name, exc)
        return {"synced": synced, "failed": failed}

    def credentials(self, agent: Agent, *, rotate: bool = False) -> dict[str, str]:
        """Return the agent's client credentials (rotating the secret if asked)."""
        if agent.status != ACTIVE:
            raise KeycloakError("credentials are only issued to active agents")
        self.sync(agent)
        if not agent.idp_client_uuid:
            raise KeycloakError("the agent has no identity yet")
        secret = (
            self.admin.regenerate_secret(agent.idp_client_uuid)
            if rotate
            else self.admin.get_secret(agent.idp_client_uuid)
        )
        return {
            "client_id": agent.client_id or "",
            "client_secret": secret,
            "token_endpoint": f"{self.admin.base_url}/realms/{self.admin.realm}"
            "/protocol/openid-connect/token",
        }

    def delete(self, agent: Agent) -> None:
        if agent.client_id:
            existing = self.admin.find_client(agent.client_id)
            if existing is not None:
                self.admin.delete_client(existing["id"])

    # -- background worker --------------------------------------------------
    def trigger(self) -> None:
        self._wake.set()

    def start(self, interval: float = 60.0) -> None:
        def run() -> None:
            while not self._stop.is_set():
                try:
                    self.reconcile_all()
                except Exception:  # keep the worker alive across DB/IdP hiccups
                    log.exception("identity reconciliation failed")
                self._wake.wait(timeout=interval)
                self._wake.clear()

        self._thread = threading.Thread(target=run, name="identity-reconciler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
