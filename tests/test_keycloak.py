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
        self.tokens = 0
        self.create_conflict_once = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/protocol/openid-connect/token"):
            self.tokens += 1
            return httpx.Response(200, json={"access_token": f"t{self.tokens}", "expires_in": 300})
        assert request.headers["authorization"].startswith("Bearer t")
        base = "/admin/realms/agentgov/clients"
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
