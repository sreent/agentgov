"""Keycloak as the agent identity provider (the open Entra Agent ID).

Each registered agent gets its own confidential OAuth client in the AgentGov
realm, with a service account for the client-credentials grant. Protocol mappers
put an ``agent_id`` claim, the gateway audience and the subject's groups into
every access token, which agentgateway validates before any tool call reaches
the governance processor.

An agent that acts for people (its blueprint's ``acts_for`` isn't ``itself``) may
exchange a person's token for one of its own whose subject is the person
(Keycloak's standard token exchange, RFC 8693). Keycloak lets a client exchange
only tokens issued for it, so each such agent also gets a client scope named after
its client ID, which adds the agent to a token's audience. The apps people use
agents from request that scope; ``AGENTGOV_PEOPLE_APP_CLIENTS`` names the apps it
is offered to.

An agent with a workload identity has no client secret: its client authenticates
with a token from its identity issuer for its subject (Keycloak's federated client
authentication), and each identity issuer is an identity provider in the realm
(``agentgov.registry.identity_issuers``).

The reconciler is level-triggered: it compares each agent's lifecycle state
with its Keycloak client and converges them, so a missed notification or a
Keycloak outage only delays convergence.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from typing import Any
from urllib.parse import quote

import httpx
from sqlalchemy import select

from agentgov import ids
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.models import ACTIVE, DISCOVERED, Agent, IdentityIssuer
from agentgov.registry import features, identity_issuers

log = logging.getLogger(__name__)

TOKEN_LIFESPAN_SECONDS = 300
EXCHANGE = "standard.token.exchange.enabled"
# A client that authenticates with its workload identity: the issuer's identity provider
# in the realm, and the agent's subject there.
FEDERATED = "federated-jwt"
FEDERATED_ISSUER = "jwt.credential.issuer"
FEDERATED_SUBJECT = "jwt.credential.sub"


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

    def add_protocol_mapper(self, uuid: str, mapper: dict[str, Any]) -> None:
        self._check(
            self._request("POST", f"/clients/{uuid}/protocol-mappers/models", json=mapper),
            "protocol mapper create",
        )

    def list_client_scopes(self) -> list[dict[str, Any]]:
        return self._check(self._request("GET", "/client-scopes"), "client scope list").json()

    def create_client_scope(self, representation: dict[str, Any]) -> str:
        resp = self._request("POST", "/client-scopes", json=representation)
        if resp.status_code == 409:
            raise KeycloakConflict(f"client scope {representation['name']} already exists")
        self._check(resp, "client scope create")
        location = resp.headers.get("Location", "")
        if location:
            return location.rstrip("/").rsplit("/", 1)[-1]
        created = next(
            (c for c in self.list_client_scopes() if c.get("name") == representation["name"]),
            None,
        )
        if created is None:
            raise KeycloakError("client scope created but could not be found")
        return created["id"]

    def delete_client_scope(self, uuid: str) -> None:
        """Delete a client scope, which also takes it off the clients that had it."""
        resp = self._request("DELETE", f"/client-scopes/{uuid}")
        if resp.status_code not in (204, 404):
            self._check(resp, "client scope delete")

    def optional_scopes(self, uuid: str) -> list[dict[str, Any]]:
        resp = self._request("GET", f"/clients/{uuid}/optional-client-scopes")
        return self._check(resp, "optional client scope list").json()

    def add_optional_scope(self, uuid: str, scope_uuid: str) -> None:
        resp = self._request("PUT", f"/clients/{uuid}/optional-client-scopes/{scope_uuid}")
        self._check(resp, "optional client scope add")

    def _check_providers(self, resp: httpx.Response, what: str) -> httpx.Response:
        if resp.status_code == 403:
            raise KeycloakError(
                f"Keycloak refused the {what}: give {self._client_id}'s service account the "
                "realm-management role manage-identity-providers"
            )
        return self._check(resp, what)

    def list_identity_providers(self) -> list[dict[str, Any]]:
        resp = self._request("GET", "/identity-provider/instances")
        return self._check_providers(resp, "identity provider list").json()

    def create_identity_provider(self, representation: dict[str, Any]) -> None:
        resp = self._request("POST", "/identity-provider/instances", json=representation)
        if resp.status_code == 409:
            raise KeycloakConflict(f"identity provider {representation['alias']} exists")
        self._check_providers(resp, "identity provider create")

    def update_identity_provider(self, alias: str, representation: dict[str, Any]) -> None:
        resp = self._request(
            "PUT", f"/identity-provider/instances/{quote(alias)}", json=representation
        )
        self._check_providers(resp, "identity provider update")

    def delete_identity_provider(self, alias: str) -> None:
        resp = self._request("DELETE", f"/identity-provider/instances/{quote(alias)}")
        if resp.status_code not in (204, 404):
            self._check_providers(resp, "identity provider delete")


def acts_for_people(agent: Agent) -> bool:
    """Whether the agent may act for people (its blueprint says so, or has no say)."""
    return agent.blueprint is None or agent.blueprint.acts_for != "itself"


def client_representation(agent: Agent, settings: Settings) -> dict[str, Any]:
    authenticator = "client-secret"
    federated: dict[str, str] = {}
    if agent.workload_issuer:
        # No secret: a token from its issuer for its subject authenticates the client.
        authenticator = FEDERATED
        federated = {
            FEDERATED_ISSUER: identity_issuers.alias(agent.workload_issuer),
            FEDERATED_SUBJECT: agent.workload_subject or "",
        }
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
        "clientAuthenticatorType": authenticator,
        "attributes": {
            "agentgov.agent_id": agent.id,
            "agentgov.managed": "true",
            "access.token.lifespan": str(TOKEN_LIFESPAN_SECONDS),
            "client_credentials.use_refresh_token": "false",
            # Exchanging a person's token for a token of its own, on their behalf.
            EXCHANGE: "true" if acts_for_people(agent) else "false",
            **federated,
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
            {
                # The groups of the person the agent acts for, as their paths ("/support").
                "name": "agentgov-groups",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-group-membership-mapper",
                "consentRequired": False,
                "config": {
                    "claim.name": "groups",
                    "full.path": "true",
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "userinfo.token.claim": "false",
                    "introspection.token.claim": "true",
                },
            },
        ],
    }


def discovery(issuer: str, http: httpx.Client) -> dict[str, Any]:
    """An OpenID Connect issuer's discovery document."""
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        resp = http.get(url, timeout=10)
        resp.raise_for_status()
        document = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise KeycloakError(f"couldn't read {url}: {exc}") from exc
    if not isinstance(document, dict) or not document.get("jwks_uri"):
        raise KeycloakError(f"{url} names no jwks_uri: give the issuer its keys_url")
    return document


# The settings AgentGov owns on its issuers' identity providers.
ISSUER_SETTINGS = (
    "issuer",
    "issuerDiscoveryUrl",
    "trustDomain",
    "bundleEndpoint",
    "jwksUrl",
    "useJwksUrl",
    "validateSignature",
    "supportsClientAssertions",
    "supportsClientAssertionReuse",
    "allowClientIdAsAudience",
    "clientId",
    "clientAuthMethod",
    "authorizationUrl",
    "tokenUrl",
    "agentgov.managed",
    "agentgov.issuer_id",
)


def issuer_representation(
    issuer: IdentityIssuer, *, enabled: bool, document: dict[str, Any] | None = None
) -> dict[str, Any]:
    """The issuer as an identity provider in Keycloak, trusted for client assertions only:
    no one signs in with it."""
    config: dict[str, str] = {"agentgov.managed": "true", "agentgov.issuer_id": issuer.id}
    if issuer.kind == identity_issuers.KUBERNETES:
        config["issuer"] = issuer.issuer
        if issuer.keys_url:
            config["issuerDiscoveryUrl"] = issuer.keys_url
    elif issuer.kind == identity_issuers.SPIFFE:
        config.update(trustDomain=issuer.issuer, bundleEndpoint=issuer.keys_url or "")
    else:
        document = document or {}
        base = issuer.issuer.rstrip("/")
        config.update(
            issuer=issuer.issuer,
            jwksUrl=issuer.keys_url or str(document.get("jwks_uri") or ""),
            useJwksUrl="true",
            validateSignature="true",
            supportsClientAssertions="true",
            supportsClientAssertionReuse="true" if issuer.allow_reuse else "false",
            # Its tokens name this audience instead of the realm (Microsoft Entra ID's do).
            allowClientIdAsAudience="true" if issuer.audience else "false",
            clientId=issuer.audience or "agentgov",
            # Keycloak's OpenID Connect providers need these; no one signs in with them.
            clientAuthMethod="private_key_jwt",
            authorizationUrl=str(document.get("authorization_endpoint") or f"{base}/authorize"),
            tokenUrl=str(document.get("token_endpoint") or f"{base}/token"),
        )
    return {
        "alias": identity_issuers.alias(issuer.name),
        "displayName": f"AgentGov: {issuer.name}",
        "providerId": issuer.kind,
        "enabled": enabled,
        "hideOnLogin": True,
        "config": config,
    }


def _issuer_differs(existing: dict[str, Any], desired: dict[str, Any]) -> bool:
    if existing.get("enabled") != desired["enabled"]:
        return True
    have, want = existing.get("config") or {}, desired["config"]
    return any(have.get(k) != want.get(k) for k in ISSUER_SETTINGS if k in want or k in have)


def scope_representation(agent: Agent) -> dict[str, Any]:
    """The client scope apps request for a person's token the agent can exchange."""
    return {
        "name": agent.client_id,
        "description": f"Lets AgentGov agent {agent.name} act for the person signed in",
        "protocol": "openid-connect",
        "attributes": {
            "agentgov.agent_id": agent.id,
            "agentgov.managed": "true",
            "include.in.token.scope": "true",
            "display.on.consent.screen": "true",
            "consent.screen.text": f"Let {agent.name} act for you",
        },
        "protocolMappers": [
            {
                "name": "agentgov-agent-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.client.audience": agent.client_id,
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "introspection.token.claim": "true",
                },
            }
        ],
    }


def _managed(representation: dict[str, Any]) -> bool:
    return (representation.get("attributes") or {}).get("agentgov.managed") == "true"


class _Scopes:
    """The realm's client scopes and the people's apps, read at most once per pass."""

    def __init__(self, admin: KeycloakAdmin, apps: list[str]) -> None:
        self.admin = admin
        self.app_ids = apps
        self._by_name: dict[str, dict[str, Any]] | None = None
        self._apps: list[tuple[str, set[str]]] | None = None

    def by_name(self) -> dict[str, dict[str, Any]]:
        if self._by_name is None:
            self._by_name = {s["name"]: s for s in self.admin.list_client_scopes()}
        return self._by_name

    def apps(self) -> list[tuple[str, set[str]]]:
        """Each people's app that exists: its UUID and the names of its optional scopes."""
        if self._apps is None:
            self._apps = []
            for client_id in self.app_ids:
                app = self.admin.find_client(client_id)
                if app is None:
                    log.warning("AGENTGOV_PEOPLE_APP_CLIENTS: no Keycloak client %s", client_id)
                    continue
                names = {s["name"] for s in self.admin.optional_scopes(app["id"])}
                self._apps.append((app["id"], names))
        return self._apps


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
    def sync(self, agent: Agent, scopes: _Scopes | None = None) -> None:
        """Converge one agent's Keycloak client with its lifecycle state."""
        if agent.status == DISCOVERED or not agent.client_id:
            return
        with self._sync_lock:
            self._sync(agent, scopes or _Scopes(self.admin, self.settings.people_apps()))

    def _sync(self, agent: Agent, scopes: _Scopes) -> None:
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
            attributes = existing.get("attributes") or {}
            authenticator = existing.get("clientAuthenticatorType")
            if (
                existing.get("enabled") != desired["enabled"]
                or existing.get("description", "") != desired["description"]
                or attributes.get("agentgov.agent_id") != agent.id
                or attributes.get(EXCHANGE, "false") != desired["attributes"][EXCHANGE]
                or authenticator != desired["clientAuthenticatorType"]
                or any(
                    attributes.get(k) != desired["attributes"][k]
                    for k in (FEDERATED_ISSUER, FEDERATED_SUBJECT)
                    if k in desired["attributes"]
                )
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
                if authenticator != desired["clientAuthenticatorType"]:
                    # Going to its workload identity, or back from it to a secret, no
                    # secret from before authenticates it again.
                    self.admin.regenerate_secret(existing["id"])
            # Clients made by earlier versions lack the mappers added since.
            present = {m.get("name") for m in existing.get("protocolMappers") or []}
            for mapper in desired["protocolMappers"]:
                if mapper["name"] not in present:
                    self.admin.add_protocol_mapper(existing["id"], mapper)
        if agent.idp_client_uuid:
            self._sync_people_scope(agent, scopes)
        agent.identity_synced_at = ids.utcnow()
        agent.identity_error = None

    def _sync_people_scope(self, agent: Agent, scopes: _Scopes) -> None:
        """The agent's client scope, offered to the people's apps, while it acts for people."""
        name = agent.client_id or ""
        scope = scopes.by_name().get(name)
        if scope is not None and not _managed(scope):
            raise KeycloakError(f"client scope {name} exists, and AgentGov didn't make it")
        if not acts_for_people(agent):
            if scope is not None:
                self.admin.delete_client_scope(scope["id"])
                del scopes.by_name()[name]
                log.info("removed client scope %s: %s acts only for itself", name, agent.name)
            return
        if scope is None:
            representation = scope_representation(agent)
            scope = {**representation, "id": self.admin.create_client_scope(representation)}
            scopes.by_name()[name] = scope
            log.info("created client scope %s for agent %s", name, agent.name)
        for app_uuid, optional in scopes.apps():
            if name not in optional:
                self.admin.add_optional_scope(app_uuid, scope["id"])
                optional.add(name)

    def sync_issuers(self, session: Any) -> None:
        """Converge the realm's identity providers with the identity issuers: one per
        issuer, enabled while the issuer is approved and workload-identity is on."""
        on = features.is_on(session, "workload-identity")
        try:
            existing = {p["alias"]: p for p in self.admin.list_identity_providers()}
        except (KeycloakError, httpx.HTTPError) as exc:
            for issuer in identity_issuers.list_all(session):
                issuer.sync_error = str(exc)[:500]
            raise
        wanted = set()
        for issuer in identity_issuers.list_all(session):
            alias = identity_issuers.alias(issuer.name)
            wanted.add(alias)
            try:
                document = None
                if issuer.kind == identity_issuers.OIDC and not issuer.keys_url:
                    document = discovery(issuer.issuer, self.admin._http)
                enabled = on and issuer.status == identity_issuers.APPROVED
                desired = issuer_representation(issuer, enabled=enabled, document=document)
                current = existing.get(alias)
                if current is not None and current.get("providerId") != desired["providerId"]:
                    self.admin.delete_identity_provider(alias)
                    current = None
                if current is None:
                    self.admin.create_identity_provider(desired)
                    log.info("created identity provider %s for issuer %s", alias, issuer.name)
                elif _issuer_differs(current, desired):
                    merged = {**current, **desired}
                    merged["config"] = {**(current.get("config") or {}), **desired["config"]}
                    self.admin.update_identity_provider(alias, merged)
                    log.info("updated identity provider %s (enabled=%s)", alias, enabled)
                issuer.synced_at = ids.utcnow()
                issuer.sync_error = None
            except (KeycloakError, httpx.HTTPError) as exc:
                issuer.sync_error = str(exc)[:500]
                log.warning("identity provider for issuer %s: %s", issuer.name, exc)
        for alias, provider in existing.items():
            stale = alias.startswith(identity_issuers.ALIAS_PREFIX) and alias not in wanted
            if stale and (provider.get("config") or {}).get("agentgov.managed") == "true":
                self.admin.delete_identity_provider(alias)
                log.info("removed identity provider %s: its issuer is gone", alias)

    def reconcile_all(self) -> dict[str, int]:
        synced = failed = 0
        scopes = _Scopes(self.admin, self.settings.people_apps())
        with self.db.session() as session:
            # The identity providers first: agents' clients name them.
            try:
                self.sync_issuers(session)
            except (KeycloakError, httpx.HTTPError) as exc:
                log.warning("identity issuers: %s", exc)
            for agent in session.scalars(select(Agent).where(Agent.status != DISCOVERED)).unique():
                try:
                    self.sync(agent, scopes)
                    synced += 1
                except (KeycloakError, httpx.HTTPError) as exc:
                    failed += 1
                    agent.identity_error = str(exc)[:500]
                    log.warning("identity sync failed for %s: %s", agent.name, exc)
        return {"synced": synced, "failed": failed}

    def credentials(self, agent: Agent, *, rotate: bool = False) -> dict[str, str]:
        """Return the agent's client credentials (rotating the secret if asked), or, for an
        agent with a workload identity, how it authenticates without a secret."""
        if agent.status != ACTIVE:
            raise KeycloakError("credentials are only issued to active agents")
        self.sync(agent)
        if not agent.idp_client_uuid:
            raise KeycloakError("the agent has no identity yet")
        endpoint = f"{self.admin.base_url}/realms/{self.admin.realm}/protocol/openid-connect/token"
        if agent.workload_issuer:
            if rotate:
                raise KeycloakError(
                    "the agent has no secret to rotate: it authenticates with its workload identity"
                )
            return {
                "client_id": agent.client_id or "",
                "method": "workload-identity",
                "issuer": agent.workload_issuer,
                "subject": agent.workload_subject or "",
                "token_endpoint": endpoint,
            }
        secret = (
            self.admin.regenerate_secret(agent.idp_client_uuid)
            if rotate
            else self.admin.get_secret(agent.idp_client_uuid)
        )
        return {
            "client_id": agent.client_id or "",
            "method": "client-secret",
            "client_secret": secret,
            "token_endpoint": endpoint,
        }

    def delete(self, agent: Agent) -> None:
        if agent.client_id:
            existing = self.admin.find_client(agent.client_id)
            if existing is not None:
                self.admin.delete_client(existing["id"])
            scope = _Scopes(self.admin, []).by_name().get(agent.client_id)
            if scope is not None and _managed(scope):
                self.admin.delete_client_scope(scope["id"])

    # -- background worker --------------------------------------------------
    def trigger(self) -> None:
        self._wake.set()

    def start(
        self,
        interval: float = 60.0,
        *,
        leading: Callable[[], bool] | None = None,
        exclusive: Callable[[], AbstractContextManager[Any]] | None = None,
    ) -> None:
        """Reconcile every agent when triggered and every ``interval`` seconds; with
        ``leading``, only while this replica leads, and inside ``exclusive`` (one run at a
        time across replicas)."""

        def run() -> None:
            while not self._stop.is_set():
                if leading is None or leading():
                    try:
                        with exclusive() if exclusive is not None else nullcontext():
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
