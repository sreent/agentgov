"""Keycloak identity reconciliation against a simulated Admin REST API."""

from __future__ import annotations

import json
import time
import uuid
from collections import Counter
from typing import Any

import httpx
import pytest

from agentgov.identity.keycloak import IdentityReconciler, KeycloakAdmin, KeycloakError
from agentgov.registry import agents, blueprints


class FakeKeycloak:
    """Just enough of Keycloak's token endpoint and admin API."""

    def __init__(self) -> None:
        self.clients: dict[str, dict[str, Any]] = {}
        self.secrets: dict[str, str] = {}
        self.scopes: dict[str, dict[str, Any]] = {}
        self.optional: dict[str, set[str]] = {}  # client UUID -> optional client scope UUIDs
        self.providers: dict[str, dict[str, Any]] = {}  # identity providers, by alias
        self.forbid_providers = False  # the service account may not manage them
        self.discovery: dict[str, dict[str, Any]] = {}  # OpenID Connect issuers' documents
        self.tokens = 0
        self.create_conflict_once = False
        # Another control-plane replica makes the next client scope, or adds the next
        # optional scope, between our lookup and ours.
        self.scope_conflict_once = False
        self.link_conflict_once = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/protocol/openid-connect/token"):
            self.tokens += 1
            return httpx.Response(200, json={"access_token": f"t{self.tokens}", "expires_in": 300})
        if path.endswith("/.well-known/openid-configuration"):
            issuer = str(request.url).removesuffix("/.well-known/openid-configuration")
            document = self.discovery.get(issuer)
            return httpx.Response(200, json=document) if document else httpx.Response(404)
        assert request.headers["authorization"].startswith("Bearer t")
        providers = "/admin/realms/agentgov/identity-provider/instances"
        if path.startswith(providers):
            if self.forbid_providers:
                return httpx.Response(403, json={"error": "HTTP 403 Forbidden"})
            alias = path.removeprefix(providers).strip("/")
            if request.method == "GET":
                return httpx.Response(200, json=list(self.providers.values()))
            if request.method == "POST":
                rep = json.loads(request.content)
                if rep["alias"] in self.providers:
                    return httpx.Response(409)
                self.providers[rep["alias"]] = rep
                return httpx.Response(201)
            if request.method == "PUT":
                self.providers[alias] = json.loads(request.content)
                return httpx.Response(204)
            self.providers.pop(alias, None)
            return httpx.Response(204)
        scopes = "/admin/realms/agentgov/client-scopes"
        if path == scopes and request.method == "GET":
            return httpx.Response(200, json=list(self.scopes.values()))
        if path == scopes and request.method == "POST":
            sid = str(uuid.uuid4())
            self.scopes[sid] = {**json.loads(request.content), "id": sid}
            if self.scope_conflict_once:
                self.scope_conflict_once = False
                return httpx.Response(409, json={"errorMessage": "exists"})
            return httpx.Response(201, headers={"Location": f"http://kc{scopes}/{sid}"})
        if path.startswith(scopes + "/") and request.method == "DELETE":
            sid = path.rsplit("/", 1)[-1]
            self.scopes.pop(sid, None)
            for assigned in self.optional.values():
                assigned.discard(sid)
            return httpx.Response(204)
        base = "/admin/realms/agentgov/clients"
        if "/optional-client-scopes" in path:
            uid = path.removeprefix(base + "/").split("/")[0]
            assigned = self.optional.setdefault(uid, set())
            if request.method == "PUT":
                assigned.add(path.rsplit("/", 1)[-1])
                if self.link_conflict_once:
                    self.link_conflict_once = False
                    return httpx.Response(409, json={"errorMessage": "exists"})
                return httpx.Response(204)
            return httpx.Response(200, json=[self.scopes[sid] for sid in assigned])
        if path.endswith("/protocol-mappers/models") and request.method == "POST":
            uid = path.removeprefix(base + "/").split("/")[0]
            mapper = {**json.loads(request.content), "id": str(uuid.uuid4())}
            self.clients[uid].setdefault("protocolMappers", []).append(mapper)
            return httpx.Response(201)
        if "/protocol-mappers/models/" in path and request.method == "DELETE":
            uid = path.removeprefix(base + "/").split("/")[0]
            mid = path.rsplit("/", 1)[-1]
            mappers = self.clients[uid].get("protocolMappers") or []
            self.clients[uid]["protocolMappers"] = [m for m in mappers if m.get("id") != mid]
            return httpx.Response(204)
        if path == base and request.method == "GET":
            wanted = request.url.params.get("clientId")
            return httpx.Response(
                200, json=[c for c in self.clients.values() if c["clientId"] == wanted]
            )
        if path == base and request.method == "POST":
            rep = json.loads(request.content)
            if self.create_conflict_once:
                # Someone else created it between our lookup and our create.
                self.create_conflict_once = False
                self._store(rep)
                return httpx.Response(409, json={"errorMessage": "exists"})
            uid = self._store(rep)
            return httpx.Response(201, headers={"Location": f"http://kc{base}/{uid}"})
        uid = path.removeprefix(base + "/").split("/")[0]
        if path.endswith("/client-secret"):
            if request.method == "POST":
                self.secrets[uid] = uuid.uuid4().hex
            return httpx.Response(200, json={"type": "secret", "value": self.secrets[uid]})
        if request.method == "PUT":
            self.clients[uid] = json.loads(request.content)
            return httpx.Response(204)
        if request.method == "DELETE":
            self.clients.pop(uid, None)
            return httpx.Response(204)
        return httpx.Response(404)

    def _store(self, rep: dict[str, Any]) -> str:
        uid = str(uuid.uuid4())
        mappers = [{**m, "id": str(uuid.uuid4())} for m in rep.get("protocolMappers") or []]
        self.clients[uid] = {**rep, "id": uid, "protocolMappers": mappers}
        self.secrets[uid] = uuid.uuid4().hex
        return uid

    def by_client_id(self, client_id: str) -> dict[str, Any]:
        return next(c for c in self.clients.values() if c["clientId"] == client_id)

    def scope(self, name: str) -> dict[str, Any] | None:
        return next((c for c in self.scopes.values() if c["name"] == name), None)

    def optional_names(self, client_id: str) -> set[str]:
        assigned = self.optional.get(self.by_client_id(client_id)["id"], set())
        return {self.scopes[sid]["name"] for sid in assigned}


@pytest.fixture
def keycloak() -> FakeKeycloak:
    return FakeKeycloak()


@pytest.fixture
def reconciler(rt, settings, keycloak) -> IdentityReconciler:
    http = httpx.Client(transport=httpx.MockTransport(keycloak.handler))
    admin = KeycloakAdmin("http://kc", "agentgov", "agentgov-control-plane", "secret", http=http)
    return IdentityReconciler(rt.db, settings, admin)


def _agent(rt, settings, approve=True):
    with rt.db.session() as s:
        blueprints.create(s, {"name": "bp", "require_sponsor": False}, actor="t")
        return agents.register(
            s, settings, {"name": "bot", "blueprint": "bp"}, actor="t", approve=approve
        ).id


def test_no_client_until_approved(rt, settings, keycloak, reconciler) -> None:
    _agent(rt, settings, approve=False)
    reconciler.reconcile_all()
    assert keycloak.clients == {}


def test_active_agent_gets_a_service_account_client(rt, settings, keycloak, reconciler) -> None:
    agent_id = _agent(rt, settings)
    assert reconciler.reconcile_all() == {"synced": 1, "failed": 0}
    client = keycloak.by_client_id("agent-bot")
    assert client["enabled"] is True
    assert client["serviceAccountsEnabled"] is True
    assert client["standardFlowEnabled"] is False
    mappers = {m["protocolMapper"]: m["config"] for m in client["protocolMappers"]}
    assert mappers["oidc-hardcoded-claim-mapper"]["claim.value"] == agent_id
    assert mappers["oidc-audience-mapper"]["included.custom.audience"] == "agentgov-gateway"
    with rt.db.session() as s:
        agent = agents.get(s, "bot")
        assert agent.idp_client_uuid == client["id"]
        assert agent.identity_synced_at is not None


def test_blocking_disables_the_client(rt, settings, keycloak, reconciler) -> None:
    _agent(rt, settings)
    reconciler.reconcile_all()
    with rt.db.session() as s:
        agents.transition(s, settings, agents.get(s, "bot"), "block", actor="t")
    reconciler.reconcile_all()
    assert keycloak.by_client_id("agent-bot")["enabled"] is False
    with rt.db.session() as s:
        agents.transition(s, settings, agents.get(s, "bot"), "unblock", actor="t")
    reconciler.reconcile_all()
    assert keycloak.by_client_id("agent-bot")["enabled"] is True


def test_concurrent_creation_is_tolerated(rt, settings, keycloak, reconciler) -> None:
    _agent(rt, settings)
    keycloak.create_conflict_once = True
    assert reconciler.reconcile_all() == {"synced": 1, "failed": 0}
    assert len(keycloak.clients) == 1


def test_credentials_and_rotation(rt, settings, keycloak, reconciler) -> None:
    _agent(rt, settings)
    with rt.db.session() as s:
        agent = agents.get(s, "bot")
        first = reconciler.credentials(agent)
        rotated = reconciler.credentials(agent, rotate=True)
    assert first["client_id"] == "agent-bot"
    assert first["client_secret"] != rotated["client_secret"]


def test_credentials_only_for_active_agents(rt, settings, reconciler) -> None:
    _agent(rt, settings, approve=False)
    with rt.db.session() as s, pytest.raises(KeycloakError):
        reconciler.credentials(agents.get(s, "bot"))


def test_outage_is_recorded_on_the_agent(rt, settings) -> None:
    def down(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    admin = KeycloakAdmin(
        "http://kc", "agentgov", "cp", "s", http=httpx.Client(transport=httpx.MockTransport(down))
    )
    reconciler = IdentityReconciler(rt.db, settings, admin)
    _agent(rt, settings)
    assert reconciler.reconcile_all() == {"synced": 0, "failed": 1}
    with rt.db.session() as s:
        assert "connection refused" in agents.get(s, "bot").identity_error


def _people_reconciler(rt, settings, keycloak, apps: str = "chat") -> IdentityReconciler:
    http = httpx.Client(transport=httpx.MockTransport(keycloak.handler))
    admin = KeycloakAdmin("http://kc", "agentgov", "agentgov-control-plane", "secret", http=http)
    return IdentityReconciler(rt.db, settings.with_overrides(people_app_clients=apps), admin)


def test_agents_that_act_for_people_can_exchange_their_tokens(rt, settings, keycloak) -> None:
    keycloak._store({"clientId": "chat"})  # the app people use agents from
    reconciler = _people_reconciler(rt, settings, keycloak, apps="chat, missing-app")
    _agent(rt, settings)
    assert reconciler.reconcile_all() == {"synced": 1, "failed": 0}
    client = keycloak.by_client_id("agent-bot")
    assert client["attributes"]["standard.token.exchange.enabled"] == "true"
    mappers = {m["name"]: m["config"] for m in client["protocolMappers"]}
    assert mappers["agentgov-groups"]["claim.name"] == "groups"
    # The app asks for scope agent-bot to get a person's token the agent can exchange.
    scope = keycloak.scope("agent-bot")
    assert scope is not None and scope["attributes"]["agentgov.managed"] == "true"
    [audience] = scope["protocolMappers"]
    assert audience["config"]["included.client.audience"] == "agent-bot"
    assert keycloak.optional_names("chat") == {"agent-bot"}
    reconciler.reconcile_all()  # converged: nothing more to do
    assert len(keycloak.scopes) == 1


def test_agents_that_act_only_for_themselves_cannot(rt, settings, keycloak) -> None:
    keycloak._store({"clientId": "chat"})
    reconciler = _people_reconciler(rt, settings, keycloak)
    _agent(rt, settings)
    reconciler.reconcile_all()
    with rt.db.session() as s:
        blueprints.update(s, blueprints.get(s, "bp"), {"acts_for": "itself"}, actor="t")
    reconciler.reconcile_all()
    client = keycloak.by_client_id("agent-bot")
    assert client["attributes"]["standard.token.exchange.enabled"] == "false"
    assert keycloak.scope("agent-bot") is None
    assert keycloak.optional_names("chat") == set()
    with rt.db.session() as s:
        blueprints.update(s, blueprints.get(s, "bp"), {"acts_for": "people"}, actor="t")
    reconciler.reconcile_all()
    assert keycloak.by_client_id("agent-bot")["attributes"]["standard.token.exchange.enabled"] == (
        "true"
    )
    assert keycloak.optional_names("chat") == {"agent-bot"}


def test_clients_from_earlier_versions_get_the_new_mappers(rt, settings, keycloak) -> None:
    reconciler = _people_reconciler(rt, settings, keycloak, apps="")
    _agent(rt, settings)
    reconciler.reconcile_all()
    client = keycloak.by_client_id("agent-bot")
    client["protocolMappers"] = [
        m for m in client["protocolMappers"] if m["name"] != "agentgov-groups"
    ]
    del client["attributes"]["standard.token.exchange.enabled"]
    reconciler.reconcile_all()
    client = keycloak.by_client_id("agent-bot")
    assert "agentgov-groups" in {m["name"] for m in client["protocolMappers"]}
    assert client["attributes"]["standard.token.exchange.enabled"] == "true"


def test_another_replica_making_the_scope_meanwhile_is_tolerated(rt, settings, keycloak) -> None:
    keycloak._store({"clientId": "chat"})
    keycloak.scope_conflict_once = keycloak.link_conflict_once = True
    reconciler = _people_reconciler(rt, settings, keycloak)
    _agent(rt, settings)
    assert reconciler.reconcile_all() == {"synced": 1, "failed": 0}
    assert [s["name"] for s in keycloak.scopes.values()] == ["agent-bot"]
    assert keycloak.optional_names("chat") == {"agent-bot"}


def test_a_scope_agentgov_did_not_make_is_left_alone(rt, settings, keycloak) -> None:
    keycloak.scopes["s1"] = {"id": "s1", "name": "agent-bot", "attributes": {}}
    reconciler = _people_reconciler(rt, settings, keycloak, apps="")
    _agent(rt, settings)
    assert reconciler.reconcile_all() == {"synced": 0, "failed": 1}
    with rt.db.session() as s:
        assert "AgentGov didn't make it" in agents.get(s, "bot").identity_error
    assert keycloak.scopes["s1"]["attributes"] == {}


def test_deleting_an_agent_removes_its_scope(rt, settings, keycloak) -> None:
    reconciler = _people_reconciler(rt, settings, keycloak, apps="")
    _agent(rt, settings)
    reconciler.reconcile_all()
    with rt.db.session() as s:
        reconciler.delete(agents.get(s, "bot"))
    assert keycloak.clients == {} and keycloak.scopes == {}


# ---------------------------------------------------------------- public clients


def _public(rt, settings, **data):
    with rt.db.session() as s:
        blueprints.create(
            s, {"name": "assistants", "require_sponsor": False, "acts_for": "people"}, actor="t"
        )
        spec = {"name": "vscode", "blueprint": "assistants", "client_type": "public", **data}
        return agents.register(s, settings, spec, actor="t", approve=True).id


def test_people_sign_in_to_a_public_client(rt, settings, keycloak) -> None:
    keycloak._store({"clientId": "chat"})
    reconciler = _people_reconciler(rt, settings, keycloak)
    agent_id = _public(rt, settings)
    assert reconciler.reconcile_all() == {"synced": 1, "failed": 0}
    client = keycloak.by_client_id("agent-vscode")
    assert client["publicClient"] is True
    assert client["standardFlowEnabled"] is True
    assert client["serviceAccountsEnabled"] is False
    assert client["directAccessGrantsEnabled"] is False
    # Back to the machine itself, at any port, and with PKCE.
    assert client["redirectUris"] == ["http://127.0.0.1/*", "http://localhost/*"]
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    # The person's own token: nothing to exchange, so no scope for people's apps.
    assert client["attributes"]["standard.token.exchange.enabled"] == "false"
    assert keycloak.scope("agent-vscode") is None
    mappers = {m["name"]: m["config"] for m in client["protocolMappers"]}
    assert mappers["agentgov-agent-id"]["claim.value"] == agent_id
    assert mappers["agentgov-gateway-audience"]["included.custom.audience"] == "agentgov-gateway"
    assert mappers["agentgov-sign-in"]["claim.name"] == "agentgov_sign_in"
    assert mappers["agentgov-sign-in"]["jsonType.label"] == "boolean"
    with rt.db.session() as s:
        creds = reconciler.credentials(agents.get(s, "vscode"))
        assert creds["method"] == "sign-in" and "client_secret" not in creds
        assert creds["redirect_uris"] == ["http://127.0.0.1/*", "http://localhost/*"]
        with pytest.raises(KeycloakError, match="no secret to rotate"):
            reconciler.credentials(agents.get(s, "vscode"), rotate=True)


def test_a_client_turns_public_and_back(rt, settings, keycloak) -> None:
    keycloak._store({"clientId": "chat"})
    reconciler = _people_reconciler(rt, settings, keycloak)
    _agent(rt, settings)
    reconciler.reconcile_all()
    assert keycloak.scope("agent-bot") is not None
    uris = ["http://127.0.0.1/callback", "https://vscode.dev/redirect"]
    with rt.db.session() as s:
        changes = {"client_type": "public", "redirect_uris": uris}
        agents.update(s, agents.get(s, "bot"), changes, actor="t")
    reconciler.reconcile_all()
    client = keycloak.by_client_id("agent-bot")
    assert client["publicClient"] is True and client["serviceAccountsEnabled"] is False
    assert client["redirectUris"] == uris
    assert "agentgov-sign-in" in {m["name"] for m in client["protocolMappers"]}
    assert keycloak.scope("agent-bot") is None
    reconciler.reconcile_all()  # converged
    before = keycloak.secrets[client["id"]]
    with rt.db.session() as s:
        changes = {"client_type": "service", "redirect_uris": []}
        agents.update(s, agents.get(s, "bot"), changes, actor="t")
    reconciler.reconcile_all()
    client = keycloak.by_client_id("agent-bot")
    assert client["publicClient"] is False and client["serviceAccountsEnabled"] is True
    assert client["standardFlowEnabled"] is False and client["redirectUris"] == []
    # Its tokens are its own again, with a new secret, and don't say anyone signed in.
    assert keycloak.secrets[client["id"]] != before
    assert "agentgov-sign-in" not in {m["name"] for m in client["protocolMappers"]}
    assert keycloak.scope("agent-bot") is not None


# ------------------------------------------------------------- workload identity


def _issuers(rt, *specs: dict[str, Any]) -> None:
    from agentgov.registry import identity_issuers

    with rt.db.session() as s:
        for spec in specs:
            identity_issuers.create(s, spec, actor="t")


CLUSTER = {
    "name": "cluster",
    "kind": "kubernetes",
    "issuer": "https://k8s.example.com",
    "keys_url": "https://k8s.example.com",
}
SPIRE = {
    "name": "spire",
    "kind": "spiffe",
    "issuer": "spiffe://example.org",
    "keys_url": "https://spire.example.org/bundle",
}
ENTRA = {
    "name": "entra",
    "kind": "oidc",
    "issuer": "https://login.microsoftonline.com/tid/v2.0",
    "audience": "api://agentgov",
}


def test_each_issuer_is_an_identity_provider(rt, settings, keycloak, reconciler) -> None:
    keycloak.discovery["https://login.microsoftonline.com/tid/v2.0"] = {
        "jwks_uri": "https://login.microsoftonline.com/tid/discovery/v2.0/keys",
        "authorization_endpoint": "https://login.microsoftonline.com/tid/oauth2/v2.0/authorize",
        "token_endpoint": "https://login.microsoftonline.com/tid/oauth2/v2.0/token",
    }
    _issuers(rt, CLUSTER, SPIRE, ENTRA)
    reconciler.reconcile_all()
    cluster = keycloak.providers["agentgov-cluster"]
    assert (cluster["providerId"], cluster["enabled"], cluster["hideOnLogin"]) == (
        "kubernetes",
        True,
        True,
    )
    assert cluster["config"]["issuer"] == "https://k8s.example.com"
    assert cluster["config"]["issuerDiscoveryUrl"] == "https://k8s.example.com"
    spire = keycloak.providers["agentgov-spire"]["config"]
    assert (spire["trustDomain"], spire["bundleEndpoint"]) == (
        "spiffe://example.org",
        "https://spire.example.org/bundle",
    )
    entra = keycloak.providers["agentgov-entra"]["config"]
    assert entra["jwksUrl"] == "https://login.microsoftonline.com/tid/discovery/v2.0/keys"
    assert entra["supportsClientAssertions"] == "true"
    # Entra ID's tokens carry the app's audience, not the realm's URL.
    assert (entra["allowClientIdAsAudience"], entra["clientId"]) == ("true", "api://agentgov")
    assert entra["supportsClientAssertionReuse"] == "false"
    with rt.db.session() as s:
        from agentgov.registry import identity_issuers

        assert all(i.synced_at and not i.sync_error for i in identity_issuers.list_all(s))


def test_blocked_issuers_and_the_feature_switch_disable_providers(
    rt, settings, keycloak, reconciler
) -> None:
    from agentgov.registry import features, identity_issuers

    _issuers(rt, CLUSTER)
    reconciler.reconcile_all()
    with rt.db.session() as s:
        identity_issuers.set_status(s, identity_issuers.get(s, "cluster"), "block", actor="t")
    reconciler.reconcile_all()
    assert keycloak.providers["agentgov-cluster"]["enabled"] is False
    with rt.db.session() as s:
        identity_issuers.set_status(s, identity_issuers.get(s, "cluster"), "unblock", actor="t")
        features.set_mode(s, settings, "workload-identity", "off", actor="t")
    reconciler.reconcile_all()
    assert keycloak.providers["agentgov-cluster"]["enabled"] is False
    with rt.db.session() as s:
        features.set_mode(s, settings, "workload-identity", "on", actor="t")
    reconciler.reconcile_all()
    assert keycloak.providers["agentgov-cluster"]["enabled"] is True


def test_providers_of_deleted_issuers_go_but_others_stay(
    rt, settings, keycloak, reconciler
) -> None:
    from agentgov.registry import identity_issuers

    keycloak.providers["github"] = {"alias": "github", "providerId": "github", "config": {}}
    keycloak.providers["agentgov-by-hand"] = {"alias": "agentgov-by-hand", "config": {}}
    _issuers(rt, CLUSTER)
    reconciler.reconcile_all()
    with rt.db.session() as s:
        identity_issuers.delete(s, identity_issuers.get(s, "cluster"), actor="t")
    reconciler.reconcile_all()
    assert set(keycloak.providers) == {"github", "agentgov-by-hand"}


def test_an_issuer_keycloak_wont_take_says_why(rt, settings, keycloak, reconciler) -> None:
    from agentgov.registry import identity_issuers

    keycloak.forbid_providers = True
    _issuers(rt, CLUSTER, {**ENTRA, "audience": None})
    _agent(rt, settings)
    assert reconciler.reconcile_all() == {"synced": 1, "failed": 0}  # agents still sync
    keycloak.forbid_providers = False
    reconciler.reconcile_all()  # Entra ID's discovery document isn't there
    with rt.db.session() as s:
        assert identity_issuers.get(s, "cluster").sync_error is None
        assert "couldn't read" in identity_issuers.get(s, "entra").sync_error
    keycloak.forbid_providers = True
    reconciler.reconcile_all()
    with rt.db.session() as s:
        assert "manage-identity-providers" in identity_issuers.get(s, "cluster").sync_error


def test_agents_with_a_workload_identity_have_no_secret(rt, settings, keycloak, reconciler) -> None:
    _issuers(rt, CLUSTER)
    _agent(rt, settings)
    reconciler.reconcile_all()
    client = keycloak.by_client_id("agent-bot")
    before = keycloak.secrets[client["id"]]
    subject = "system:serviceaccount:agents:bot"
    with rt.db.session() as s:
        agents.update(
            s,
            agents.get(s, "bot"),
            {"workload_identity": {"issuer": "cluster", "subject": subject}},
            actor="t",
        )
    reconciler.reconcile_all()
    client = keycloak.by_client_id("agent-bot")
    assert client["clientAuthenticatorType"] == "federated-jwt"
    assert client["attributes"]["jwt.credential.issuer"] == "agentgov-cluster"
    assert client["attributes"]["jwt.credential.sub"] == subject
    # The secret it had can't authenticate it any more.
    assert keycloak.secrets[client["id"]] != before
    with rt.db.session() as s:
        creds = reconciler.credentials(agents.get(s, "bot"))
        assert creds["method"] == "workload-identity" and "client_secret" not in creds
        assert (creds["issuer"], creds["subject"]) == ("cluster", subject)
        with pytest.raises(KeycloakError, match="no secret to rotate"):
            reconciler.credentials(agents.get(s, "bot"), rotate=True)
        # Back to a secret: a new one.
        agents.update(s, agents.get(s, "bot"), {"workload_identity": None}, actor="t")
    reconciler.reconcile_all()
    client = keycloak.by_client_id("agent-bot")
    assert client["clientAuthenticatorType"] == "client-secret"
    with rt.db.session() as s:
        assert reconciler.credentials(agents.get(s, "bot"))["method"] == "client-secret"


def test_the_api_says_what_token_authenticates_an_agent(settings, keycloak) -> None:
    from starlette.testclient import TestClient

    from agentgov.api.app import create_app
    from agentgov.runtime import Runtime
    from tests.conftest import ADMIN

    settings = settings.with_overrides(keycloak_issuer="https://id.example.com/realms/agentgov")
    rt = Runtime(settings)
    rt.init_db()
    http = httpx.Client(transport=httpx.MockTransport(keycloak.handler))
    admin = KeycloakAdmin("http://kc", "agentgov", "agentgov-control-plane", "secret", http=http)
    rt.identity = IdentityReconciler(rt.db, settings, admin)
    keycloak.discovery[ENTRA["issuer"]] = {"jwks_uri": "https://login.example.com/keys"}
    _issuers(rt, CLUSTER, SPIRE, ENTRA)
    with rt.db.session() as s:
        blueprints.create(s, {"name": "bp", "require_sponsor": False}, actor="t")
        for name, issuer, subject in (
            ("pod", "cluster", "system:serviceaccount:agents:pod"),
            ("svid", "spire", "spiffe://example.org/agents/svid"),
            ("entra", "entra", "6f1c5e1a-0000-4000-8000-000000000001"),
        ):
            identity = {"issuer": issuer, "subject": subject}
            data = {"name": name, "blueprint": "bp", "workload_identity": identity}
            agents.register(s, settings, data, actor="t", approve=True)
        agents.register(s, settings, {"name": "plain", "blueprint": "bp"}, actor="t", approve=True)
    rt.identity.reconcile_all()
    token_endpoint = "https://id.example.com/realms/agentgov/protocol/openid-connect/token"
    with TestClient(create_app(settings, runtime=rt, background=False)) as client:

        def creds(name: str) -> dict[str, Any]:
            resp = client.post(f"/v1/agents/{name}/credentials", json={}, headers=ADMIN)
            resp.raise_for_status()
            return resp.json()

        pod = creds("pod")
        assert pod["method"] == "workload-identity" and "client_secret" not in pod
        assert pod["token_endpoint"] == token_endpoint
        # Its token's audience is the realm, as Keycloak expects of client assertions...
        assert pod["assertion_audience"] == "https://id.example.com/realms/agentgov"
        assert pod["assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        svid = creds("svid")
        assert svid["assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
        # ...unless the issuer can't do that: Microsoft Entra ID names the app.
        assert creds("entra")["assertion_audience"] == "api://agentgov"
        plain = creds("plain")
        assert plain["method"] == "client-secret" and plain["client_secret"]
        assert "assertion_type" not in plain
        rotate = client.post("/v1/agents/pod/credentials", json={"rotate": True}, headers=ADMIN)
        assert rotate.status_code == 409 and "no secret to rotate" in rotate.json()["detail"]
        # A public client: where people sign in to it. Nothing secret, nothing recorded.
        with rt.db.session() as s:
            data = {"name": "vscode", "blueprint": "bp", "client_type": "public"}
            agents.register(s, settings, data, actor="t", approve=True)
        before = client.get("/v1/ledger", params={"type": "agent.credentials_read"}, headers=ADMIN)
        vscode = creds("vscode")
        assert vscode["method"] == "sign-in" and "client_secret" not in vscode
        assert vscode["issuer"] == "https://id.example.com/realms/agentgov"
        assert vscode["authorization_endpoint"] == (
            "https://id.example.com/realms/agentgov/protocol/openid-connect/auth"
        )
        assert vscode["token_endpoint"] == token_endpoint
        assert vscode["audience"] == "agentgov-gateway"
        after = client.get("/v1/ledger", params={"type": "agent.credentials_read"}, headers=ADMIN)
        assert len(after.json()) == len(before.json())
        rotate = client.post("/v1/agents/vscode/credentials", json={"rotate": True}, headers=ADMIN)
        assert rotate.status_code == 409 and "public client" in rotate.json()["detail"]
    rt.db.dispose()


# ------------------------------------------------------ passes that sync what changed


def _counted(keycloak: FakeKeycloak) -> tuple[KeycloakAdmin, Counter[str]]:
    """An admin client to ``keycloak`` that counts the clients it looks up."""
    looked_up: Counter[str] = Counter()

    def handler(request: httpx.Request) -> httpx.Response:
        client_id = request.url.params.get("clientId")
        if request.method == "GET" and client_id:
            looked_up[client_id] += 1
        return keycloak.handler(request)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    admin = KeycloakAdmin("http://kc", "agentgov", "agentgov-control-plane", "secret", http=http)
    return admin, looked_up


def test_a_pass_syncs_only_the_agents_whose_clients_should_change(rt, settings, keycloak) -> None:
    admin, looked_up = _counted(keycloak)
    reconciler = IdentityReconciler(rt.db, settings.with_overrides(people_app_clients=""), admin)
    with rt.db.session() as s:
        blueprints.create(s, {"name": "bp", "require_sponsor": False}, actor="t")
        for name in ("one", "two"):
            agents.register(s, settings, {"name": name, "blueprint": "bp"}, actor="t", approve=True)
    assert reconciler.reconcile_all(full=False) == {"synced": 2, "failed": 0}  # new ones
    looked_up.clear()
    assert reconciler.reconcile_all(full=False) == {"synced": 0, "failed": 0}
    assert not looked_up  # Keycloak isn't asked about either
    with rt.db.session() as s:
        agents.update(s, agents.get(s, "one"), {"description": "Answers tickets"}, actor="t")
    assert reconciler.reconcile_all(full=False) == {"synced": 1, "failed": 0}
    assert set(looked_up) == {"agent-one"}
    assert keycloak.by_client_id("agent-one")["description"] == "Answers tickets"
    # A change to their blueprint changes both clients: they may act for people no more.
    with rt.db.session() as s:
        blueprints.update(s, blueprints.get(s, "bp"), {"acts_for": "itself"}, actor="t")
    assert reconciler.reconcile_all(full=False) == {"synced": 2, "failed": 0}
    attributes = keycloak.by_client_id("agent-two")["attributes"]
    assert attributes["standard.token.exchange.enabled"] == "false"


def test_a_full_pass_repairs_what_was_changed_in_keycloak(
    rt, settings, keycloak, reconciler
) -> None:
    _agent(rt, settings)
    reconciler.reconcile_all(full=False)
    keycloak.clients.clear()  # someone deleted the client in Keycloak itself
    assert reconciler.reconcile_all(full=False) == {"synced": 0, "failed": 0}
    assert keycloak.clients == {}
    assert reconciler.reconcile_all(full=True) == {"synced": 1, "failed": 0}
    assert keycloak.by_client_id("agent-bot")["enabled"] is True


def test_a_sync_that_failed_is_tried_again(rt, settings, keycloak) -> None:
    down = {"now": True}

    def handler(request: httpx.Request) -> httpx.Response:
        if down["now"]:
            raise httpx.ConnectError("connection refused")
        return keycloak.handler(request)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    reconciler = IdentityReconciler(
        rt.db, settings, KeycloakAdmin("http://kc", "agentgov", "cp", "s", http=http)
    )
    _agent(rt, settings)
    assert reconciler.reconcile_all(full=False) == {"synced": 0, "failed": 1}
    down["now"] = False
    assert reconciler.reconcile_all(full=False) == {"synced": 1, "failed": 0}
    with rt.db.session() as s:
        assert agents.get(s, "bot").identity_error is None


def test_the_worker_syncs_every_agent_first_then_what_changed(
    settings, reconciler, monkeypatch
) -> None:
    passes: list[bool] = []

    def reconcile_all(*, full: bool = True) -> dict[str, int]:
        passes.append(full)
        return {"synced": 0, "failed": 0}

    def until(check: Any) -> bool:
        deadline = time.monotonic() + 10
        while not check() and time.monotonic() < deadline:
            time.sleep(0.01)
        return bool(check())

    monkeypatch.setattr(reconciler, "reconcile_all", reconcile_all)
    leading = {"now": True}
    reconciler.start(interval=0.01, full_every=3600, leading=lambda: leading["now"])
    try:
        assert until(lambda: len(passes) >= 3)
        leading["now"] = False
        time.sleep(0.1)
        before = len(passes)
        leading["now"] = True
        assert until(lambda: len(passes) > before)
    finally:
        reconciler.stop()
    assert passes[:3] == [True, False, False]
    assert passes[before] is True  # leading again, it starts with every agent
