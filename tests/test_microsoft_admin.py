"""Acting in Microsoft 365 and Power Platform as the administrator signed in through Entra ID."""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.registry import platforms
from agentgov.runtime import Runtime
from tests.conftest import ADMIN
from tests.test_platforms import bot, connector
from tests.test_sso import (
    CLIENT_ID,
    CLIENT_SECRET,
    CSRF,
    FakeProvider,
    at_the_cli,
    cli_session,
    cli_sign_in,
    sign_in,
)

TENANT = "11111111-2222-3333-4444-555555555555"
ENTRA_ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
POWER_PLATFORM = "https://api.powerplatform.com"
GRAPH = "https://graph.microsoft.com"


class FakeEntra(FakeProvider):
    """Microsoft Entra ID: app roles in the ID token, refresh tokens, a token per API."""

    def __init__(self) -> None:
        super().__init__()
        self.issuer = ENTRA_ISSUER
        self.refresh_tokens: set[str] = set()
        self.refreshes: list[str] = []  # the scope of each refresh

    def tokens(self, query: dict[str, str], user: dict[str, Any]) -> dict[str, Any]:
        assert "offline_access" in query["scope"].split()
        body = super().tokens(query, {**user, "id_claims": {"roles": user.get("roles", [])}})
        body["refresh_token"] = self._new_refresh_token()
        return body

    def _new_refresh_token(self) -> str:
        token = "rt-" + secrets.token_urlsafe(8)
        self.refresh_tokens.add(token)
        return token

    def handle(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if request.url.path == f"/{TENANT}/oauth2/v2.0/token" and form.get("grant_type") == (
            "refresh_token"
        ):
            expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
            assert request.headers["authorization"] == expected
            if form["refresh_token"] not in self.refresh_tokens:
                return httpx.Response(
                    400,
                    json={
                        "error": "invalid_grant",
                        "error_description": "AADSTS70008: The refresh token has expired.",
                    },
                )
            self.refresh_tokens.discard(form["refresh_token"])  # Entra rotates them
            self.refreshes.append(form["scope"])
            resource = form["scope"].removesuffix("/.default")
            return httpx.Response(
                200,
                json={
                    "access_token": f"token-for:{resource}",
                    "refresh_token": self._new_refresh_token(),
                    "expires_in": 3599,
                },
            )
        return super().handle(request)


class FakeMicrosoftApis:
    """The Power Platform API (quarantine, inventory) and Graph's package block."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.status = 200
        self.rows = [
            bot("bot-sales", "Sales Helper", connectors=[connector("shared_sql", "Query")]),
            bot("bot-hr", "HR FAQ"),
            bot("bot-it", "IT Helpdesk"),
        ]

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        host = f"{request.url.scheme}://{request.url.host}"
        expected = {POWER_PLATFORM: POWER_PLATFORM, GRAPH: GRAPH}[host]
        assert request.headers["authorization"] == f"Bearer token-for:{expected}"
        self.calls.append((request.method, url))
        if self.status != 200:
            return httpx.Response(
                self.status,
                json={"error": {"code": "Forbidden", "message": "The caller lacks the role."}},
            )
        if "/resourcequery/resources/query" in url:
            body = json.loads(request.content)
            assert body["TableName"] == "PowerPlatformResources"
            assert body["Clauses"][0]["Values"] == ["'microsoft.copilotstudio/agents'"]
            # Two pages: the first carries a skip token.
            if not body["Options"]["SkipToken"]:
                page = {"data": self.rows[:2], "skipToken": "page-2", "count": 2}
            else:
                assert body["Options"]["SkipToken"] == "page-2"
                page = {"data": self.rows[2:], "count": 1}
            return httpx.Response(200, json={"totalRecords": len(self.rows), **page})
        if "/botQuarantine/" in url or "/catalog/packages/" in url:
            return httpx.Response(204)
        return httpx.Response(404)


@pytest.fixture
def entra() -> FakeEntra:
    return FakeEntra()


@pytest.fixture
def apis() -> FakeMicrosoftApis:
    return FakeMicrosoftApis()


@pytest.fixture
def entra_settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'entra.db'}",
        admin_token="test-admin",
        service_token="test-service",
        posture_interval_seconds=0,
        oidc_issuer=ENTRA_ISSUER,
        oidc_client_id=CLIENT_ID,
        oidc_client_secret=CLIENT_SECRET,
        oidc_roles_claim="roles",
        microsoft_admin_actions=True,
    )


@pytest.fixture
def entra_client(
    entra_settings: Settings, entra: FakeEntra, apis: FakeMicrosoftApis
) -> Iterator[TestClient]:
    runtime = Runtime(
        entra_settings,
        oidc_http=httpx.Client(transport=httpx.MockTransport(entra.handle)),
        microsoft_http=httpx.Client(transport=httpx.MockTransport(apis.handle)),
    )
    with TestClient(create_app(entra_settings, runtime=runtime, background=False)) as client:
        yield client


def admin_signs_in(client: TestClient, entra: FakeEntra) -> None:
    resp = sign_in(client, entra, sub="aad-alice", roles=["agentgov-admin"])
    assert resp.status_code == 302 and resp.headers["location"] == "/ui/", resp.headers


def import_bots(client: TestClient) -> None:
    client.post(
        "/v1/platforms/copilot-studio/import",
        json=[bot("bot-sales", "Sales Helper")],
        headers=ADMIN,
    ).raise_for_status()


class TestSignIn:
    def test_entra_endpoints_and_roles(self, entra_client, entra) -> None:
        start = entra_client.get("/auth/login", follow_redirects=False)
        location = urlsplit(start.headers["location"])
        assert f"{location.scheme}://{location.netloc}{location.path}" == (
            f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize"
        )
        admin_signs_in(entra_client, entra)
        session = entra_client.get("/auth/session").json()
        assert session["roles"] == ["admin"] and session["microsoft"] is True

    def test_needs_entra_sign_in(self, settings) -> None:
        with pytest.raises(ValueError, match="AGENTGOV_MICROSOFT_ADMIN_ACTIONS"):
            settings.with_overrides(microsoft_admin_actions=True).validate()


class TestQuarantine:
    def test_block_and_unblock_a_copilot_studio_agent(self, entra_client, entra, apis) -> None:
        import_bots(entra_client)
        admin_signs_in(entra_client, entra)
        resp = entra_client.post("/v1/agents/sales-helper/platform/block", headers=CSRF)
        assert resp.status_code == 200, resp.text
        assert resp.json() == {
            "agent": "sales-helper",
            "platform": "Copilot Studio",
            "blocked": True,
        }
        assert apis.calls == [
            (
                "POST",
                f"{POWER_PLATFORM}/copilotstudio/environments/env-sales/bots/bot-sales"
                "/api/botQuarantine/SetAsQuarantined?api-version=1",
            )
        ]
        view = entra_client.get("/v1/agents/sales-helper", headers=ADMIN).json()["platforms"][0]
        assert view["quarantined"] is True
        entry = entra_client.get(
            "/v1/ledger", params={"type": "platform.agent_*"}, headers=ADMIN
        ).json()[0]
        assert entry["type"] == "platform.agent_blocked"
        assert entry["actor"] == "admin:alice@example.com"
        assert entry["resource"] == "copilot-studio/bot-sales"

        entra_client.post("/v1/agents/sales-helper/platform/unblock", headers=CSRF)
        assert apis.calls[-1][1].endswith("/SetAsUnquarantined?api-version=1")
        assert entra.refreshes == [f"{POWER_PLATFORM}/.default"]  # the token was reused

    def test_microsoft_365_agents_are_blocked_through_graph(self, entra_client, entra, apis):
        rt = entra_client.app.state.rt
        with rt.db.session() as s:
            platforms.record_microsoft_365(
                s,
                [{"id": "T_expenses", "displayName": "Expense Helper", "type": "custom"}],
                include_types={"custom"},
            )
        admin_signs_in(entra_client, entra)
        resp = entra_client.post("/v1/agents/expense-helper/platform/block", headers=CSRF)
        assert resp.json()["platform"] == "Microsoft 365"
        assert apis.calls == [
            ("POST", f"{GRAPH}/beta/copilot/admin/catalog/packages/T_expenses/block")
        ]
        view = entra_client.get("/v1/agents/expense-helper", headers=ADMIN).json()["platforms"]
        assert view[0]["blocked"] is True

    def test_from_the_cli(self, entra_client, entra, apis) -> None:
        import_bots(entra_client)
        session = cli_session(entra_client, entra, sub="aad-alice", roles=["agentgov-admin"])
        assert session["microsoft"] is True
        bearer = {"Authorization": f"Bearer {session['token']}"}
        resp = entra_client.post("/v1/agents/sales-helper/platform/block", headers=bearer)
        assert resp.status_code == 200, resp.text
        assert apis.calls[0][1].endswith("/SetAsQuarantined?api-version=1")
        # `agentgov logout` forgets the Microsoft sign-in too.
        entra_client.post("/auth/logout", headers=bearer)
        assert entra_client.app.state.rt.delegations._grants == {}

    def test_a_refused_cli_code_forgets_the_microsoft_sign_in(self, entra_client, entra) -> None:
        _, back = cli_sign_in(entra_client, entra, sub="aad-alice", roles=["agentgov-admin"])
        assert len(entra_client.app.state.rt.delegations._grants) == 1  # waiting for the CLI
        guess = {"code": at_the_cli(back)["code"], "verifier": secrets.token_urlsafe(64)}
        assert entra_client.post("/auth/cli/token", json=guess).status_code == 400
        assert entra_client.app.state.rt.delegations._grants == {}

    def test_only_a_signed_in_administrator(self, entra_client, client) -> None:
        import_bots(entra_client)
        resp = entra_client.post("/v1/agents/sales-helper/platform/block", headers=ADMIN)
        assert resp.status_code == 409
        assert "signed-in administrator" in resp.json()["detail"]
        # Not set up at all.
        import_bots(client)
        resp = client.post("/v1/agents/sales-helper/platform/block", headers=ADMIN)
        assert resp.status_code == 409 and "not set up" in resp.json()["detail"]

    def test_agents_that_run_elsewhere(self, entra_client, entra) -> None:
        entra_client.post(
            "/v1/agents", json={"name": "gateway-bot"}, headers=ADMIN
        ).raise_for_status()
        admin_signs_in(entra_client, entra)
        resp = entra_client.post("/v1/agents/gateway-bot/platform/block", headers=CSRF)
        assert resp.status_code == 409
        assert "not an agent on Microsoft 365 or Copilot Studio" in resp.json()["detail"]

    def test_microsoft_refuses(self, entra_client, entra, apis) -> None:
        import_bots(entra_client)
        admin_signs_in(entra_client, entra)
        apis.status = 403
        resp = entra_client.post("/v1/agents/sales-helper/platform/block", headers=CSRF)
        assert resp.status_code == 502
        detail = resp.json()["detail"]
        assert "The caller lacks the role" in detail and "AI administrator" in detail
        assert (
            entra_client.get(
                "/v1/ledger", params={"type": "platform.agent_*"}, headers=ADMIN
            ).json()
            == []
        )

    def test_signing_out_forgets_the_microsoft_sign_in(self, entra_client, entra) -> None:
        import_bots(entra_client)
        admin_signs_in(entra_client, entra)
        rt = entra_client.app.state.rt
        [session_id] = list(rt.delegations._grants)
        entra_client.post("/auth/logout", headers=CSRF).raise_for_status()
        assert not rt.delegations.has(session_id)

        # An admin ending someone's sessions does too.
        admin_signs_in(entra_client, entra)
        assert len(rt.delegations._grants) == 1
        entra_client.post("/v1/access/people/aad-alice/sign-out", headers=ADMIN).raise_for_status()
        assert rt.delegations._grants == {}

    def test_an_expired_microsoft_sign_in(self, entra_client, entra) -> None:
        import_bots(entra_client)
        admin_signs_in(entra_client, entra)
        entra.refresh_tokens.clear()  # Entra no longer honours it
        resp = entra_client.post("/v1/agents/sales-helper/platform/block", headers=CSRF)
        assert resp.status_code == 409
        assert "AADSTS70008" in resp.json()["detail"]

    def test_after_a_restart(self, entra_client, entra) -> None:
        import_bots(entra_client)
        admin_signs_in(entra_client, entra)
        entra_client.app.state.rt.delegations._grants.clear()  # memory only
        assert entra_client.get("/auth/session").json()["microsoft"] is False
        resp = entra_client.post("/v1/agents/sales-helper/platform/block", headers=CSRF)
        assert resp.status_code == 409 and "sign in again" in resp.json()["detail"]


class TestInventorySync:
    def test_sync_as_the_signed_in_admin(self, entra_client, entra, apis) -> None:
        admin_signs_in(entra_client, entra)
        resp = entra_client.post("/v1/platforms/copilot-studio/sync", headers=CSRF)
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"created": 3, "updated": 0, "skipped": 0, "findings": 0}
        assert [c[1] for c in apis.calls] == [
            f"{POWER_PLATFORM}/resourcequery/resources/query?api-version=2024-10-01"
        ] * 2
        overview = entra_client.get("/v1/platforms", headers=ADMIN).json()
        assert overview["admin_actions"] is True
        studio = overview["sources"][1]
        assert studio["agents"] == 3 and studio["last_sync"]["ok"] is True
        entry = entra_client.get("/v1/ledger", params={"type": "platform.*"}, headers=ADMIN).json()[
            0
        ]
        assert entry["type"] == "platform.imported"
        assert entry["actor"] == "admin:alice@example.com"

    def test_a_refused_sync_is_reported(self, entra_client, entra, apis) -> None:
        admin_signs_in(entra_client, entra)
        apis.status = 403
        resp = entra_client.post("/v1/platforms/copilot-studio/sync", headers=CSRF)
        assert resp.status_code == 502
        last = entra_client.get("/v1/platforms", headers=ADMIN).json()["sources"][1]["last_sync"]
        assert last["ok"] is False and "ResourceQuery.Resources.Read" in last["message"]

    def test_a_sync_keeps_a_quarantine(self, entra_client, entra, apis) -> None:
        admin_signs_in(entra_client, entra)
        entra_client.post("/v1/platforms/copilot-studio/sync", headers=CSRF).raise_for_status()
        entra_client.post("/v1/agents/sales-helper/platform/block", headers=CSRF)
        # The inventory doesn't report quarantines; the next sync must not forget it.
        entra_client.post("/v1/platforms/copilot-studio/sync", headers=CSRF).raise_for_status()
        view = entra_client.get("/v1/agents/sales-helper", headers=ADMIN).json()["platforms"][0]
        assert view["quarantined"] is True
        # When the inventory does report it, the inventory wins.
        apis.rows[0]["properties"]["isQuarantined"] = False
        entra_client.post("/v1/platforms/copilot-studio/sync", headers=CSRF).raise_for_status()
        view = entra_client.get("/v1/agents/sales-helper", headers=ADMIN).json()["platforms"][0]
        assert view["quarantined"] is False
