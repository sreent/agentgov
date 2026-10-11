"""Keycloak identity reconciliation against a simulated Admin REST API."""

from __future__ import annotations

import json
import uuid
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
        self.tokens = 0
        self.create_conflict_once = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/protocol/openid-connect/token"):
            self.tokens += 1
            return httpx.Response(200, json={"access_token": f"t{self.tokens}", "expires_in": 300})
        assert request.headers["authorization"].startswith("Bearer t")
        scopes = "/admin/realms/agentgov/client-scopes"
        if path == scopes and request.method == "GET":
            return httpx.Response(200, json=list(self.scopes.values()))
        if path == scopes and request.method == "POST":
            sid = str(uuid.uuid4())
            self.scopes[sid] = {**json.loads(request.content), "id": sid}
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
                return httpx.Response(204)
            return httpx.Response(200, json=[self.scopes[sid] for sid in assigned])
        if path.endswith("/protocol-mappers/models") and request.method == "POST":
            uid = path.removeprefix(base + "/").split("/")[0]
            self.clients[uid].setdefault("protocolMappers", []).append(json.loads(request.content))
            return httpx.Response(201)
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
        self.clients[uid] = {**rep, "id": uid}
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
