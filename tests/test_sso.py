"""Administrator single sign-on against a fake OIDC provider."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import stat
import time
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import update

from agentgov import cli, ids
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.identity.sso import LOGOUT_EVENT, display_name, roles_from_claims
from agentgov.models import AdminSession, CliLogin
from agentgov.registry import findings
from agentgov.runtime import Runtime
from tests.conftest import ADMIN, SERVICE, seed
from tests.test_cli import _Shared, runner

ISSUER = "https://idp.test/realms/agentgov"
CLIENT_ID = "agentgov-admin"
CLIENT_SECRET = "test-oidc-secret"
CSRF = {"X-AgentGov-CSRF": "1"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class FakeProvider:
    """Issues codes and RS256 tokens like Keycloak (realm roles in the access token)."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        self.jwks = {"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "RS256"}]}
        self.codes: dict[str, dict[str, Any]] = {}
        self.issuer = ISSUER

    def authorize(self, url: str, **user: Any) -> tuple[str, str]:
        """What the provider does after the person signs in: returns ``(state, code)``."""
        query = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        assert query["client_id"] == CLIENT_ID and query["code_challenge_method"] == "S256"
        code = secrets.token_urlsafe(16)
        self.codes[code] = {"query": query, "user": user}
        return query["state"], code

    def sign(self, claims: dict[str, Any], *, key: Any = None) -> str:
        return jwt.encode(claims, key or self.key, algorithm="RS256", headers={"kid": "k1"})

    def tokens(self, query: dict[str, str], user: dict[str, Any]) -> dict[str, Any]:
        now = int(time.time())
        base = {"iss": self.issuer, "sub": user.get("sub", "user-1"), "iat": now, "exp": now + 300}
        id_claims = {
            **base,
            "aud": CLIENT_ID,
            "nonce": query["nonce"],
            "email": user.get("email", "alice@example.com"),
            "email_verified": True,
            "preferred_username": "alice",
            **user.get("id_claims", {}),
        }
        access = {
            **base,
            "azp": CLIENT_ID,
            "realm_access": {"roles": user.get("roles", [])},
            **user.get("access_claims", {}),
        }
        id_token = user.get("id_token") or self.sign(id_claims, key=user.get("id_key"))
        return {"id_token": id_token, "access_token": self.sign(access), "token_type": "Bearer"}

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(("/certs", "/keys")):
            return httpx.Response(200, json=self.jwks)
        if request.url.path.endswith("/token"):
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
            grant = self.codes.pop(form.get("code", ""), None)
            if request.headers.get("authorization") != expected or grant is None:
                return httpx.Response(400, json={"error": "invalid_grant"})
            query = grant["query"]
            challenge = _b64url(hashlib.sha256(form["code_verifier"].encode()).digest())
            if (
                challenge != query["code_challenge"]
                or form["redirect_uri"] != query["redirect_uri"]
            ):
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json=self.tokens(query, grant["user"]))
        return httpx.Response(404)


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
def sso_settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'agentgov.db'}",
        admin_token="test-admin",
        service_token="test-service",
        posture_interval_seconds=0,
        oidc_issuer=ISSUER,
        oidc_client_secret=CLIENT_SECRET,
    )


@pytest.fixture
def sso(sso_settings: Settings, provider: FakeProvider) -> Iterator[TestClient]:
    runtime = Runtime(
        sso_settings, oidc_http=httpx.Client(transport=httpx.MockTransport(provider.handle))
    )
    with TestClient(create_app(sso_settings, runtime=runtime, background=False)) as client:
        yield client


def sign_in(client: TestClient, provider: FakeProvider, **user: Any) -> httpx.Response:
    start = client.get("/auth/login", follow_redirects=False)
    assert start.status_code == 302
    state, code = provider.authorize(start.headers["location"], **user)
    return client.get(
        "/auth/callback", params={"state": state, "code": code}, follow_redirects=False
    )


def error_code(resp: httpx.Response) -> str | None:
    assert resp.status_code == 302
    return parse_qs(urlsplit(resp.headers["location"]).query).get("sso_error", [None])[0]


CLI_PORT = 8765


def cli_start(client: TestClient, verifier: str) -> httpx.Response:
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    params = {"cli_port": CLI_PORT, "cli_challenge": challenge}
    return client.get("/auth/login", params=params, follow_redirects=False)


def cli_sign_in(
    client: TestClient, provider: FakeProvider, **user: Any
) -> tuple[str, httpx.Response]:
    """The browser half of `agentgov login`: the verifier, and where the browser went next."""
    verifier = secrets.token_urlsafe(64)
    start = cli_start(client, verifier)
    assert start.status_code == 302, start.text
    state, code = provider.authorize(start.headers["location"], **user)
    back = client.get(
        "/auth/callback", params={"state": state, "code": code}, follow_redirects=False
    )
    return verifier, back


def at_the_cli(resp: httpx.Response) -> dict[str, str]:
    """The query the browser took back to the CLI's loopback listener."""
    target = urlsplit(resp.headers["location"])
    assert resp.status_code == 302
    assert f"{target.scheme}://{target.netloc}{target.path}" == (
        f"http://127.0.0.1:{CLI_PORT}/callback"
    )
    return {k: v[0] for k, v in parse_qs(target.query).items()}


def cli_session(client: TestClient, provider: FakeProvider, **user: Any) -> dict[str, Any]:
    verifier, back = cli_sign_in(client, provider, **user)
    code = at_the_cli(back)["code"]
    resp = client.post("/auth/cli/token", json={"code": code, "verifier": verifier})
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestSignIn:
    def test_info_advertises_single_sign_on(self, sso) -> None:
        assert sso.get("/v1/info").json()["sso"] == {"enabled": True, "login_url": "/auth/login"}

    def test_login_redirects_to_the_provider_with_pkce(self, sso) -> None:
        resp = sso.get("/auth/login", follow_redirects=False)
        target = urlsplit(resp.headers["location"])
        query = parse_qs(target.query)
        assert f"{target.scheme}://{target.netloc}{target.path}" == (
            f"{ISSUER}/protocol/openid-connect/auth"
        )
        assert query["redirect_uri"] == ["http://localhost:8000/auth/callback"]
        assert query["code_challenge_method"] == ["S256"] and len(query["code_challenge"][0]) == 43
        assert "httponly" in resp.headers["set-cookie"].lower()

    def test_a_signed_in_person_gets_their_mapped_roles(self, sso, provider) -> None:
        resp = sign_in(sso, provider, roles=["agentgov-approver", "agentgov-auditor", "offline"])
        assert (resp.status_code, resp.headers["location"]) == (302, "/ui/")
        cookie = resp.headers["set-cookie"].lower()
        assert (
            "agentgov_session=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
        )
        me = sso.get("/v1/me").json()
        assert me["name"] == "alice@example.com"
        assert (me["role"], me["roles"], me["via"]) == (
            "approver",
            ["approver", "auditor"],
            "session",
        )
        login = sso.get("/v1/ledger", params={"type": "admin.login"}, headers=ADMIN).json()
        assert login[0]["actor"] == "sso:alice@example.com"
        assert login[0]["details"]["roles"] == ["approver", "auditor"]

    def test_roles_can_come_from_the_id_token(self, sso, provider) -> None:
        sign_in(sso, provider, id_claims={"realm_access": {"roles": ["agentgov-admin"]}})
        assert sso.get("/v1/me").json()["roles"] == ["admin"]

    def test_cookie_writes_need_the_csrf_header(self, sso, provider) -> None:
        sign_in(sso, provider, roles=["agentgov-approver"])
        resp = sso.post("/v1/findings/fnd_missing/resolve")
        assert resp.status_code == 403 and "X-AgentGov-CSRF" in resp.json()["detail"]
        assert sso.post("/v1/findings/fnd_missing/resolve", headers=CSRF).status_code == 404

    def test_roles_limit_what_a_session_may_do(self, sso, provider) -> None:
        sign_in(sso, provider, roles=["agentgov-auditor"])
        assert sso.get("/v1/overview").status_code == 200
        blocked = sso.post("/v1/agents/support-bot/block", json={}, headers=CSRF)
        assert blocked.status_code == 403
        assert sso.post("/v1/findings/fnd_x/resolve", headers=CSRF).status_code == 403

    def test_logout_ends_the_session_and_points_at_the_provider(self, sso, provider) -> None:
        sign_in(sso, provider, roles=["agentgov-admin"])
        assert sso.post("/auth/logout").status_code == 403  # CSRF header required
        out = sso.post("/auth/logout", headers=CSRF).json()
        target = urlsplit(out["logout_url"])
        query = parse_qs(target.query)
        assert target.path.endswith("/protocol/openid-connect/logout")
        assert query["post_logout_redirect_uri"] == ["http://localhost:8000/ui/"]
        assert query["client_id"] == [CLIENT_ID] and query["id_token_hint"][0].count(".") == 2
        assert sso.get("/v1/me").status_code == 401
        events = [e["type"] for e in sso.get("/v1/ledger", headers=ADMIN).json()]
        assert events[:2] == ["admin.logout", "admin.login"]

    def test_back_to_the_page_the_link_was_for(self, sso, provider) -> None:
        # An email links to an issue: once signed in, the person is there, not on a list.
        start = sso.get(
            "/auth/login", params={"next": "#/findings/fnd_123"}, follow_redirects=False
        )
        state, code = provider.authorize(start.headers["location"], roles=["agentgov-admin"])
        back = sso.get(
            "/auth/callback", params={"state": state, "code": code}, follow_redirects=False
        )
        assert back.headers["location"] == "/ui/#/findings/fnd_123"
        # Only a page of the UI: anywhere else is refused before the sign-in starts.
        for elsewhere in ("https://evil.test/", "//evil.test", "#//evil.test\\x"):
            refused = sso.get("/auth/login", params={"next": elsewhere}, follow_redirects=False)
            assert refused.status_code == 422, elsewhere
        assert sign_in(sso, provider, roles=["agentgov-admin"]).headers["location"] == "/ui/"

    def test_the_session_probe_always_answers(self, sso, provider) -> None:
        assert sso.get("/auth/session").json() == {"signed_in": False}
        sign_in(sso, provider, roles=["agentgov-auditor"])
        probe = sso.get("/auth/session").json()
        assert probe == {"signed_in": True, **sso.get("/v1/me").json()}
        assert probe["actor"] == "auditor:alice@example.com"
        # It describes the browser's session, not a bearer token.
        sso.cookies.clear()
        assert sso.get("/auth/session", headers=ADMIN).json() == {"signed_in": False}

    def test_other_providers_need_their_endpoints_and_roles_claim(self, tmp_path, provider) -> None:
        provider.issuer = "https://login.example.com/tenant-1/v2.0"
        oauth = "https://login.example.com/tenant-1/oauth2/v2.0"
        settings = Settings(
            database_url=f"sqlite:///{tmp_path / 'other.db'}",
            admin_token="test-admin",
            posture_interval_seconds=0,
            oidc_issuer=provider.issuer,
            oidc_client_secret=CLIENT_SECRET,
            oidc_authorization_endpoint=f"{oauth}/authorize",
            oidc_token_endpoint=f"{oauth}/token",
            oidc_jwks_url="https://login.example.com/tenant-1/discovery/v2.0/keys",
            oidc_end_session_endpoint=f"{oauth}/logout",
            oidc_roles_claim="roles",
        )
        runtime = Runtime(
            settings, oidc_http=httpx.Client(transport=httpx.MockTransport(provider.handle))
        )
        with TestClient(create_app(settings, runtime=runtime, background=False)) as client:
            start = client.get("/auth/login", follow_redirects=False)
            assert start.headers["location"].startswith(f"{oauth}/authorize?")
            resp = sign_in(client, provider, id_claims={"roles": ["agentgov-auditor", "other"]})
            assert resp.headers["location"] == "/ui/"
            assert client.get("/v1/me").json()["roles"] == ["auditor"]
            out = client.post("/auth/logout", headers=CSRF).json()
            assert out["logout_url"].startswith(f"{oauth}/logout?")

    def test_bearer_tokens_still_work(self, sso) -> None:
        assert sso.get("/v1/me", headers=ADMIN).json()["via"] == "token"

    def test_disabled_without_a_client_secret(self, client) -> None:
        assert client.get("/auth/login", follow_redirects=False).status_code == 404
        assert client.get("/v1/info").json()["sso"]["enabled"] is False
        assert client.get("/auth/session").json() == {"signed_in": False}


class TestRefusals:
    def test_the_callback_must_come_back_to_the_same_browser(self, sso, provider) -> None:
        start = sso.get("/auth/login", follow_redirects=False)
        state, code = provider.authorize(start.headers["location"], roles=["agentgov-admin"])
        sso.cookies.clear()  # another browser, e.g. a forged link
        resp = sso.get(
            "/auth/callback", params={"state": state, "code": code}, follow_redirects=False
        )
        assert error_code(resp) == "state"
        assert sso.get("/v1/me").status_code == 401

    def test_each_sign_in_completes_once(self, sso, provider) -> None:
        start = sso.get("/auth/login", follow_redirects=False)
        state, code = provider.authorize(start.headers["location"], roles=["agentgov-admin"])
        params = {"state": state, "code": code}
        assert sso.get("/auth/callback", params=params, follow_redirects=False).status_code == 302
        sso.cookies.set("agentgov_login", state, path="/auth")
        replay = sso.get("/auth/callback", params=params, follow_redirects=False)
        assert error_code(replay) == "expired"

    def test_provider_errors_are_reported(self, sso) -> None:
        resp = sso.get("/auth/callback", params={"error": "access_denied"}, follow_redirects=False)
        assert error_code(resp) == "provider"

    def test_people_without_an_agentgov_role_are_refused(self, sso, provider) -> None:
        # Unless issues or approvals sent to people let them in, to see theirs.
        _feature(sso, "issues", "off")
        assert error_code(sign_in(sso, provider, roles=["offline_access"])) == "no_role"
        assert sso.get("/v1/me").status_code == 401
        denied = sso.get("/v1/ledger", params={"type": "admin.login_denied"}, headers=ADMIN)
        assert denied.json()[0]["actor"] == "sso:alice@example.com"

    @pytest.mark.parametrize(
        ("claims", "code"),
        [
            ({"nonce": "not-this-sign-in"}, "state"),
            ({"iss": "https://evil.test/realms/agentgov"}, "token"),
            ({"aud": "some-other-client"}, "token"),
            ({"exp": 1}, "token"),
        ],
    )
    def test_id_tokens_are_validated(self, sso, provider, claims, code) -> None:
        resp = sign_in(sso, provider, roles=["agentgov-admin"], id_claims=claims)
        assert error_code(resp) == code
        assert sso.get("/v1/me").status_code == 401

    def test_tokens_signed_by_another_key_are_refused(self, sso, provider) -> None:
        resp = sign_in(sso, provider, roles=["agentgov-admin"], id_key=provider.other_key)
        assert error_code(resp) == "token"

    def test_hmac_tokens_keyed_with_the_public_key_are_refused(self, sso, provider) -> None:
        public_pem = provider.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        start = sso.get("/auth/login", follow_redirects=False)
        nonce = parse_qs(urlsplit(start.headers["location"]).query)["nonce"][0]
        now = int(time.time())
        header = _b64url(json.dumps({"alg": "HS256", "kid": "k1", "typ": "JWT"}).encode())
        body = _b64url(
            json.dumps(
                {
                    "iss": ISSUER,
                    "aud": CLIENT_ID,
                    "sub": "x",
                    "iat": now,
                    "exp": now + 300,
                    "nonce": nonce,
                    "realm_access": {"roles": ["agentgov-admin"]},
                }
            ).encode()
        )
        signature = _b64url(hmac.new(public_pem, f"{header}.{body}".encode(), "sha256").digest())
        state, code = provider.authorize(
            start.headers["location"], id_token=f"{header}.{body}.{signature}"
        )
        resp = sso.get(
            "/auth/callback", params={"state": state, "code": code}, follow_redirects=False
        )
        assert error_code(resp) == "token"

    def test_expired_sessions_are_rejected(self, sso, provider) -> None:
        sign_in(sso, provider, roles=["agentgov-admin"])
        rt = sso.app.state.rt
        with rt.db.session() as s:
            s.execute(update(AdminSession).values(expires_at=ids.utcnow() - timedelta(seconds=1)))
        assert sso.get("/v1/me").status_code == 401


def auditor_key(client: TestClient) -> dict[str, str]:
    resp = client.post("/v1/apikeys", json={"name": "reviewer", "role": "auditor"}, headers=ADMIN)
    return {"Authorization": f"Bearer {resp.json()['token']}"}


class TestAccess:
    def test_people_come_from_sign_ins_and_refusals(self, sso, provider) -> None:
        _feature(sso, "issues", "off")  # so that people without a role are refused
        sign_in(sso, provider, roles=["agentgov-approver"])
        sso.cookies.clear()
        sign_in(sso, provider, sub="user-2", email="bob@example.com", roles=["offline"])
        view = sso.get("/v1/access", headers=ADMIN).json()
        assert (view["sso_enabled"], view["bootstrap_token"]) == (True, True)
        people = {p["name"]: p for p in view["people"]}
        alice, bob = people["alice@example.com"], people["bob@example.com"]
        assert (alice["status"], alice["roles"], alice["active_sessions"]) == (
            "signed_in",
            ["approver"],
            1,
        )
        assert alice["sign_ins"] == 1 and alice["session_expires_at"]
        assert (bob["status"], bob["roles"], bob["last_refused"] is not None) == (
            "refused",
            [],
            True,
        )
        assert [s["name"] for s in view["sessions"]] == ["alice@example.com"]
        assert view["people"][0]["name"] == "bob@example.com"  # most recent first

    def test_admins_can_sign_people_out(self, sso, provider) -> None:
        sign_in(sso, provider, roles=["agentgov-auditor"])
        session_cookie = dict(sso.cookies)
        sso.cookies.clear()
        auditor = auditor_key(sso)
        assert sso.get("/v1/access", headers=auditor).status_code == 200
        assert sso.post("/v1/access/people/user-1/sign-out", headers=auditor).status_code == 403
        assert sso.post("/v1/access/people/user-1/sign-out", headers=ADMIN).json() == {"ended": 1}
        sso.cookies.update(session_cookie)
        assert sso.get("/v1/me").status_code == 401
        person = sso.get("/v1/access", headers=ADMIN).json()["people"][0]
        assert (person["status"], person["active_sessions"]) == ("signed_out", 0)
        ended = sso.get("/v1/ledger", params={"type": "admin.session_ended"}, headers=ADMIN)
        entry = ended.json()[0]
        assert (entry["actor"], entry["details"]["name"]) == (
            "admin:bootstrap",
            "alice@example.com",
        )

    def test_one_session_can_be_ended(self, sso, provider) -> None:
        sign_in(sso, provider, roles=["agentgov-admin"])
        session_id = sso.get("/v1/access").json()["sessions"][0]["id"]
        assert sso.delete(f"/v1/access/sessions/{session_id}").status_code == 403  # CSRF
        assert sso.delete(f"/v1/access/sessions/{session_id}", headers=CSRF).json() == {"ended": 1}
        assert sso.get("/v1/me").status_code == 401
        assert sso.delete(f"/v1/access/sessions/{session_id}", headers=ADMIN).status_code == 404

    def test_the_cli_lists_and_signs_people_out(self, sso, provider, monkeypatch) -> None:
        sign_in(sso, provider, roles=["agentgov-approver"])
        session_cookie = dict(sso.cookies)
        sso.cookies.clear()
        monkeypatch.setattr(cli, "_client", lambda: _Shared(sso, "test-admin"))
        listing = runner.invoke(cli.app, ["access", "list"])
        assert listing.exit_code == 0, listing.output
        assert "alice@example.com  signed_in  approver" in listing.output
        sessions = runner.invoke(cli.app, ["access", "sessions"]).output
        assert "alice@example.com" in sessions and "ses_" in sessions
        out = runner.invoke(cli.app, ["access", "sign-out", "alice@example.com"])
        assert out.output.strip() == "person/alice@example.com: signed out (1 sessions ended)"
        assert runner.invoke(cli.app, ["access", "sign-out", "nobody"]).exit_code == 2
        sso.cookies.update(session_cookie)
        assert sso.get("/v1/me").status_code == 401

    def test_available_without_single_sign_on(self, client) -> None:
        view = client.get("/v1/access", headers=ADMIN).json()
        assert view == {
            "sso_enabled": False,
            "bootstrap_token": True,
            "provider": None,
            "people": [],
            "sessions": [],
            "grants": [],
            "api_keys": {"default_days": 90, "max_days": 0},
        }


def _check(client: TestClient, sub: str, username: str) -> dict[str, Any]:
    """The processor's approval check for support-bot's call for this person."""
    agent = client.get("/v1/agents/support-bot", headers=ADMIN).json()
    check = {
        "agent_id": agent["id"],
        "action": "tools/call",
        "resource": "crm/delete_customer",
        "arguments": {"id": "c-1"},
        "reasons": ["destructive"],
        "user": {"id": sub, "username": username, "via": "exchange"},
    }
    return client.post("/v1/internal/approvals/check", json=check, headers=SERVICE).json()


def _held_for(client: TestClient, sub: str, username: str) -> dict[str, Any]:
    """An agent whose blueprint sends approvals to the person, held calling for one."""
    seed(client)
    client.patch(
        "/v1/blueprints/support", json={"approvals_by": "person"}, headers=ADMIN
    ).raise_for_status()
    return _check(client, sub, username)


def _feature(client: TestClient, name: str, mode: str) -> None:
    client.put(f"/v1/features/{name}", json={"mode": mode}, headers=ADMIN).raise_for_status()


def _approvals_by_person(client: TestClient, mode: str = "on") -> None:
    _feature(client, "approvals-by-person", mode)


class TestApprovalsByThePerson:
    def test_people_without_a_role_sign_in_to_decide_their_own(self, sso, provider) -> None:
        _approvals_by_person(sso)
        held = _held_for(sso, "user-1", "alice")
        assert (held["outcome"], held["approval"]["deciders"]) == ("created", "person")
        assert held["url"].endswith("/ui/#/approvals")
        resp = sign_in(sso, provider, sub="user-1", roles=["offline_access"])
        assert resp.headers["location"] == "/ui/"
        assert sso.get("/v1/me").json()["roles"] == ["person"]
        mine = sso.get("/v1/me/approvals", params={"status": "pending"}).json()
        assert [r["id"] for r in mine] == [held["approval"]["id"]]
        assert mine[0]["on_behalf_of"] == "alice"
        # Their requests, and nothing else.
        for path in ("/v1/approvals", "/v1/agents", "/v1/ledger", "/v1/overview"):
            assert sso.get(path).status_code == 403, path
        approval_id = held["approval"]["id"]
        decided = sso.post(f"/v1/approvals/{approval_id}/approve", json={}, headers=CSRF)
        assert decided.json()["decided_by"] == "person:alice@example.com"
        # The agent's retry for her goes through once.
        again = _check(sso, "user-1", "alice")
        assert again["outcome"] == "approved"
        entries = sso.get("/v1/ledger", params={"user": "alice"}, headers=ADMIN).json()
        assert {"approval.requested", "approval.approved", "approval.used"} <= {
            e["type"] for e in entries
        }

    def test_only_the_person_or_an_administrator_decides(self, sso, provider) -> None:
        _approvals_by_person(sso)
        held = _held_for(sso, "user-2", "bob")
        approval_id = held["approval"]["id"]
        # An approver who isn't bob, and someone else without a role.
        sign_in(sso, provider, sub="user-1", roles=["agentgov-approver"])
        refused = sso.post(f"/v1/approvals/{approval_id}/approve", json={}, headers=CSRF)
        assert refused.status_code == 403
        assert refused.json()["detail"] == (
            "bob, whom the agent acted for, or an administrator decides this request"
        )
        assert sso.get("/v1/me/approvals").json() == []
        sso.cookies.clear()
        sign_in(sso, provider, sub="user-3", roles=[])
        assert sso.get(f"/v1/approvals/{approval_id}").status_code == 403
        # Administrators can always decide.
        decided = sso.post(f"/v1/approvals/{approval_id}/deny", json={}, headers=ADMIN)
        assert decided.json()["status"] == "denied"

    def test_without_the_feature_approvers_decide(self, sso, provider) -> None:
        _feature(sso, "issues", "off")
        held = _held_for(sso, "user-1", "alice")
        assert held["approval"]["deciders"] == "approvers"
        assert error_code(sign_in(sso, provider, sub="user-1", roles=[])) == "no_role"
        sign_in(sso, provider, sub="user-9", roles=["agentgov-approver"])
        approval_id = held["approval"]["id"]
        decided = sso.post(f"/v1/approvals/{approval_id}/approve", json={}, headers=CSRF)
        assert decided.status_code == 200

    def test_turning_the_feature_off_ends_their_sessions(self, sso, provider) -> None:
        _feature(sso, "issues", "off")
        _approvals_by_person(sso)
        sign_in(sso, provider, sub="user-1", roles=[])
        assert sso.get("/v1/me").status_code == 200
        _approvals_by_person(sso, "off")
        assert sso.get("/v1/me").status_code == 401


class TestIssuesForPeople:
    def test_people_without_a_role_see_and_acknowledge_their_own(self, sso, provider) -> None:
        agent = seed(sso)
        sso.patch(
            "/v1/agents/support-bot", json={"owner": "alice@example.com"}, headers=ADMIN
        ).raise_for_status()
        rt = sso.app.state.rt
        with rt.db.session() as s:
            mine, _ = findings.raise_finding(
                s,
                type="agent.attestation_due",
                severity="medium",
                subject=agent["id"],
                agent_id=agent["id"],
                title="support-bot is due for review",
            )
            other, _ = findings.raise_finding(
                s, type="destination.failing", severity="high", subject="dst_1", title="Failing"
            )
            mine_id, other_id = mine.id, other.id
        rt.run_issues()
        # The issues feature is on: alice signs in without an AgentGov role.
        assert sign_in(sso, provider, sub="user-1", roles=[]).headers["location"] == "/ui/"
        me = sso.get("/v1/me").json()
        assert (me["roles"], me["inbox"]) == (["person"], {"issues": True, "approvals": False})
        assert [f["id"] for f in sso.get("/v1/me/issues").json()] == [mine_id]
        assert sso.get(f"/v1/findings/{mine_id}").json()["yours"] is True
        # Their issues, and nothing else.
        assert sso.get("/v1/findings").status_code == 403
        assert sso.get(f"/v1/findings/{other_id}").status_code == 403
        assert sso.post(f"/v1/findings/{other_id}/acknowledge", headers=CSRF).status_code == 403
        acked = sso.post(f"/v1/findings/{mine_id}/acknowledge", headers=CSRF)
        assert acked.json()["acknowledged_by"] == "person:alice@example.com"
        # Risks are accepted by approvers, not by the people responsible.
        body = {"reason": "fine", "until": 30}
        assert (
            sso.post(f"/v1/findings/{mine_id}/accept", json=body, headers=CSRF).status_code == 403
        )
        # Not even when they are approvers.
        sign_in(sso, provider, sub="user-1", roles=["agentgov-approver"])
        refused = sso.post(f"/v1/findings/{mine_id}/accept", json=body, headers=CSRF)
        assert refused.status_code == 403
        assert refused.json()["detail"].startswith("You own support-bot")


class TestSponsorsAttest:
    def test_sponsors_attest_their_agents_whatever_their_role(self, sso, provider) -> None:
        """Attesting is a sponsor's job: the issue that a review is due goes to them, and
        they attest without an AgentGov role. Nobody else does, but administrators."""
        seed(sso, sponsors=["Alice@Example.com"])
        sign_in(sso, provider, sub="user-1", roles=[])
        attested = sso.post("/v1/agents/support-bot/attest", json={}, headers=CSRF)
        assert attested.status_code == 200, attested.text
        assert attested.json()["attestation"]["attested_by"] == "person:alice@example.com"
        # Not someone else's agent, nor one that doesn't exist: either way, refused alike.
        sign_in(sso, provider, sub="user-2", roles=[], email="bob@example.com")
        assert sso.post("/v1/agents/support-bot/attest", json={}, headers=CSRF).status_code == 403
        assert sso.post("/v1/agents/nobody/attest", json={}, headers=CSRF).status_code == 403
        # A key that isn't an approver's attests nothing, whatever its name.
        auditor = sso.post(
            "/v1/apikeys", json={"name": "alice@example.com", "role": "auditor"}, headers=ADMIN
        ).json()["token"]
        refused = sso.post(
            "/v1/agents/support-bot/attest",
            json={},
            headers={"Authorization": f"Bearer {auditor}"},
        )
        assert refused.status_code == 403


class TestAccessPackagesForPeople:
    def test_owners_ask_for_and_review_their_agents_packages(self, sso, provider) -> None:
        seed(sso)
        sso.patch(
            "/v1/agents/support-bot", json={"owner": "alice@example.com"}, headers=ADMIN
        ).raise_for_status()
        sso.post(
            "/v1/access-packages",
            json={"name": "crm-write", "permissions": [{"server": "crm", "tools": ["update_*"]}]},
            headers=ADMIN,
        ).raise_for_status()
        sign_in(sso, provider, sub="user-1", roles=[])
        body = {"agent": "support-bot", "package": "crm-write", "reason": "Incident INC-1"}
        asked = sso.post("/v1/access-assignments", json=body, headers=CSRF)
        assert asked.status_code == 201, asked.text
        assert asked.json()["requested_by"] == "person:alice@example.com"
        assert sso.get("/v1/agents/support-bot/access-packages").status_code == 200
        # They ask; approvers decide.
        approve = f"/v1/access-assignments/{asked.json()['id']}/approve"
        assert sso.post(approve, headers=CSRF).status_code == 403
        assert sso.post(approve, headers=ADMIN).status_code == 200
        review = f"/v1/access-assignments/{asked.json()['id']}/review"
        kept = sso.post(review, json={"keep": True}, headers=CSRF)
        assert kept.status_code == 200 and kept.json()["reviewed_at"]
        # Nobody else's agents.
        sso.post(
            "/v1/agents",
            json={"name": "other-bot", "owner": "bob@example.com", "sponsors": ["bob@example.com"]},
            headers=ADMIN,
        ).raise_for_status()
        other = {**body, "agent": "other-bot"}
        assert sso.post("/v1/access-assignments", json=other, headers=CSRF).status_code == 403
        assert sso.get("/v1/agents/other-bot/access-packages").status_code == 403


class TestCliSignIn:
    def test_the_cli_gets_a_session_of_its_own(self, sso, provider) -> None:
        verifier, back = cli_sign_in(sso, provider, roles=["agentgov-admin"])
        code = at_the_cli(back)["code"]
        assert "agentgov_session" not in sso.cookies  # the browser itself stays signed out
        resp = sso.post("/auth/cli/token", json={"code": code, "verifier": verifier})
        session = resp.json()
        assert (session["name"], session["roles"], session["microsoft"]) == (
            "alice@example.com",
            ["admin"],
            False,
        )
        bearer = {"Authorization": f"Bearer {session['token']}"}
        me = sso.get("/v1/me", headers=bearer).json()
        assert (me["actor"], me["via"]) == ("admin:alice@example.com", "session")
        # Browsers never send a bearer token by themselves: no CSRF header needed.
        assert sso.post("/v1/findings/fnd_missing/resolve", headers=bearer).status_code == 404
        login = sso.get("/v1/ledger", params={"type": "admin.login"}, headers=ADMIN).json()
        assert login[0]["details"]["client"] == "cli"
        again = sso.post("/auth/cli/token", json={"code": code, "verifier": verifier})
        assert again.status_code == 400  # each code works once

        assert sso.post("/auth/logout", headers=bearer).status_code == 200
        assert sso.get("/v1/me", headers=bearer).status_code == 401

    def test_only_the_program_that_started_it(self, sso, provider) -> None:
        verifier, back = cli_sign_in(sso, provider, roles=["agentgov-admin"])
        code = at_the_cli(back)["code"]
        guess = {"code": code, "verifier": secrets.token_urlsafe(64)}
        assert sso.post("/auth/cli/token", json=guess).status_code == 400
        # A wrong verifier uses the code up.
        right = {"code": code, "verifier": verifier}
        assert sso.post("/auth/cli/token", json=right).status_code == 400
        assert sso.get("/v1/access", headers=ADMIN).json()["sessions"] == []

    def test_the_code_expires(self, sso, provider) -> None:
        verifier, back = cli_sign_in(sso, provider, roles=["agentgov-admin"])
        with sso.app.state.rt.db.session() as s:
            s.execute(update(CliLogin).values(expires_at=ids.utcnow() - timedelta(seconds=1)))
        code = at_the_cli(back)["code"]
        resp = sso.post("/auth/cli/token", json={"code": code, "verifier": verifier})
        assert resp.status_code == 400 and "expired" in resp.json()["detail"]

    def test_failures_go_back_to_the_cli(self, sso, provider) -> None:
        _feature(sso, "issues", "off")
        _, back = cli_sign_in(sso, provider, roles=["offline"])
        assert at_the_cli(back) == {"error": "no_role"}

        start = cli_start(sso, secrets.token_urlsafe(64))
        state, _ = provider.authorize(start.headers["location"])
        params = {"state": state, "error": "access_denied"}
        refused = sso.get("/auth/callback", params=params, follow_redirects=False)
        assert at_the_cli(refused) == {"error": "provider"}

        # A callback this browser didn't start goes to the admin UI, never to a CLI.
        start = cli_start(sso, secrets.token_urlsafe(64))
        state, code = provider.authorize(start.headers["location"], roles=["agentgov-admin"])
        sso.cookies.clear()
        params = {"state": state, "code": code}
        forged = sso.get("/auth/callback", params=params, follow_redirects=False)
        assert error_code(forged) == "state"

    def test_the_cli_parameters_are_checked(self, sso) -> None:
        challenge = _b64url(hashlib.sha256(b"verifier").digest())
        for params in (
            {"cli_port": 80, "cli_challenge": challenge},  # not a port a CLI can listen on
            {"cli_port": CLI_PORT, "cli_challenge": "not-a-challenge"},
        ):
            assert sso.get("/auth/login", params=params, follow_redirects=False).status_code == 422
        alone = sso.get("/auth/login", params={"cli_port": CLI_PORT}, follow_redirects=False)
        assert alone.status_code == 400


class _AsConfigured:
    """Stands in for ``cli._client()``: the test's client, with the token the CLI would send."""

    def __init__(self, client: TestClient) -> None:
        self.client = client

    def __enter__(self) -> TestClient:
        token = cli._token(cli._url())
        if token:
            self.client.headers["Authorization"] = f"Bearer {token}"
        return self.client

    def __exit__(self, *exc: object) -> None:
        self.client.headers.pop("Authorization", None)


@pytest.fixture
def sessions_file(sso: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """The CLI pointed at the test's control plane, with its own config directory."""
    monkeypatch.setenv("AGENTGOV_URL", "http://testserver")
    monkeypatch.setenv("AGENTGOV_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.delenv("AGENTGOV_TOKEN", raising=False)
    monkeypatch.delenv("AGENTGOV_ADMIN_TOKEN", raising=False)
    monkeypatch.setattr(cli, "_client", lambda: _AsConfigured(sso))
    return tmp_path / "config" / "sessions.json"


def a_browser(client: TestClient, provider: FakeProvider, pages: list[str], **user: Any) -> Any:
    """Stands in for ``webbrowser.open``: sign in, then go back to the CLI's real listener."""

    def open_(url: str) -> bool:
        start = client.get(url, follow_redirects=False)
        state, code = provider.authorize(start.headers["location"], **user)
        params = {"state": state, "code": code}
        back = client.get("/auth/callback", params=params, follow_redirects=False)
        pages.append(httpx.get(back.headers["location"], trust_env=False).text)
        return True

    return open_


class TestCliLogin:
    def test_login_whoami_logout(self, sso, provider, sessions_file, monkeypatch) -> None:
        pages: list[str] = []
        browser = a_browser(sso, provider, pages, roles=["agentgov-admin"])
        monkeypatch.setattr(cli.webbrowser, "open", browser)
        result = runner.invoke(cli.app, ["login"])
        assert result.exit_code == 0, result.output
        assert "Signed in to http://testserver as alice@example.com (admin) until" in result.output
        assert "signed in to the AgentGov command line as alice@example.com" in pages[0]
        assert stat.S_IMODE(sessions_file.stat().st_mode) == 0o600

        me = runner.invoke(cli.app, ["whoami"])
        assert json.loads(me.output)["actor"] == "admin:alice@example.com"
        assert json.loads(me.output)["via"] == "session"

        out = runner.invoke(cli.app, ["logout"])
        assert out.output.strip() == "Signed out of http://testserver."
        assert json.loads(sessions_file.read_text()) == {}
        assert sso.get("/v1/access", headers=ADMIN).json()["sessions"] == []
        signed_out = runner.invoke(cli.app, ["whoami"])
        assert signed_out.exit_code == 1 and "agentgov login" in signed_out.output
        again = runner.invoke(cli.app, ["logout"])
        assert again.output.strip() == "Not signed in to http://testserver."

    def test_a_refused_sign_in_is_reported(self, sso, provider, sessions_file, monkeypatch):
        _feature(sso, "issues", "off")
        pages: list[str] = []
        monkeypatch.setattr(cli.webbrowser, "open", a_browser(sso, provider, pages, roles=[]))
        result = runner.invoke(cli.app, ["login"])
        assert result.exit_code == 2
        assert "sign-in failed: you signed in, but your account has no AgentGov role" in (
            result.output
        )
        assert "Sign-in failed" in pages[0]
        assert not sessions_file.exists()

    def test_without_a_browser_it_prints_the_link(self, sso, sessions_file, monkeypatch) -> None:
        monkeypatch.setattr(cli.webbrowser, "open", lambda url: pytest.fail("opened a browser"))
        monkeypatch.setattr(cli, "LOGIN_WAIT_SECONDS", 0.2)
        result = runner.invoke(cli.app, ["login", "--no-browser"])
        assert result.exit_code == 2
        assert "http://testserver/auth/login?cli_port=" in result.output
        assert "timed out waiting for you to sign in" in result.output

    def test_an_environment_token_comes_first(
        self, sso, provider, sessions_file, monkeypatch
    ) -> None:
        monkeypatch.setenv("AGENTGOV_ADMIN_TOKEN", "test-admin")
        browser = a_browser(sso, provider, [], roles=["agentgov-auditor"])
        monkeypatch.setattr(cli.webbrowser, "open", browser)
        result = runner.invoke(cli.app, ["login"])
        assert result.exit_code == 0, result.output
        assert "unset it to use this sign-in" in result.output
        assert json.loads(runner.invoke(cli.app, ["whoami"]).output)["via"] == "token"

    def test_needs_single_sign_on(self, client, monkeypatch) -> None:
        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
        result = runner.invoke(cli.app, ["login"])
        assert result.exit_code == 2 and "has no single sign-on" in result.output


class TestClaims:
    def test_roles_from_claims(self) -> None:
        claims = {
            "realm_access": {"roles": ["agentgov-auditor", "agentgov-admin", "agentgov-root"]},
            "groups": ["/agentgov-approver"],
            "roles": "agentgov-registrar other",
        }
        assert roles_from_claims(claims, "realm_access.roles", "agentgov-") == ["admin", "auditor"]
        assert roles_from_claims(claims, "groups", "agentgov-") == ["approver"]
        assert roles_from_claims(claims, "roles", "agentgov-") == ["registrar"]
        assert roles_from_claims(claims, "missing.path", "agentgov-") == []

    def test_unverified_emails_are_not_used_as_names(self) -> None:
        claims = {"sub": "s", "email": "boss@example.com", "preferred_username": "mallory"}
        assert display_name(claims) == "mallory"
        assert display_name({**claims, "email_verified": True}) == "boss@example.com"
        assert display_name({"sub": "s"}) == "s"


class TestBackChannelLogout:
    """The identity provider ends a person's session: the AgentGov sessions that came from
    it end with it (OpenID Connect Back-Channel Logout 1.0)."""

    @staticmethod
    def logout_token(provider: FakeProvider, *, key: Any = None, **claims: Any) -> str:
        now = int(time.time())
        token = {
            "iss": provider.issuer,
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 120,
            "jti": secrets.token_hex(8),
            "events": {LOGOUT_EVENT: {}},
            **claims,
        }
        return provider.sign({k: v for k, v in token.items() if v is not None}, key=key)

    def test_the_session_the_provider_ended_ends(self, sso, provider) -> None:
        sign_in(sso, provider, roles=["agentgov-admin"], id_claims={"sid": "kc-1"})
        cli = cli_session(sso, provider, roles=["agentgov-admin"], id_claims={"sid": "kc-1"})
        sign_in(sso, provider, roles=["agentgov-admin"], id_claims={"sid": "kc-2"})
        token = self.logout_token(provider, sid="kc-1", sub="user-1")
        resp = sso.post("/auth/backchannel-logout", data={"logout_token": token})
        assert resp.status_code == 200 and resp.headers["cache-control"] == "no-store"
        # The browser's session from kc-1, and the CLI's, ended; the one from kc-2 didn't.
        cli_bearer = {"Authorization": f"Bearer {cli['token']}"}
        assert sso.get("/v1/me", headers=cli_bearer).status_code == 401
        assert sso.get("/auth/session").json()["signed_in"] is True
        ended = sso.get("/v1/ledger", params={"type": "admin.logout"}, headers=ADMIN).json()
        assert len(ended) == 2
        assert {e["reason"] for e in ended} == {"the identity provider ended the session"}
        # Naming the person alone ends all of their sessions.
        token = self.logout_token(provider, sub="user-1")
        assert sso.post("/auth/backchannel-logout", data={"logout_token": token}).status_code == 200
        assert sso.get("/auth/session").json() == {"signed_in": False}

    @pytest.mark.parametrize(
        "change",
        [
            {"aud": "another-client"},
            {"iss": "https://elsewhere.test/realms/agentgov"},
            {"events": None},
            {"events": {"http://schemas.openid.net/event/something-else": {}}},
            {"nonce": "an-id-token-has-one"},
            {"sid": None, "sub": None},
            {"exp": int(time.time()) - 600},
            {"key": "other"},
        ],
    )
    def test_anything_but_the_providers_logout_token_is_refused(
        self, sso, provider, change
    ) -> None:
        sign_in(sso, provider, roles=["agentgov-admin"], id_claims={"sid": "kc-1"})
        change = dict(change)
        key = provider.other_key if change.pop("key", None) else None
        token = self.logout_token(provider, key=key, **{"sid": "kc-1", "sub": "user-1", **change})
        resp = sso.post("/auth/backchannel-logout", data={"logout_token": token})
        assert resp.status_code == 400 and resp.json()["error"] == "invalid_request"
        assert sso.get("/auth/session").json()["signed_in"] is True

    def test_it_takes_one_logout_token_in_a_form(self, sso, provider) -> None:
        sign_in(sso, provider, roles=["agentgov-admin"], id_claims={"sid": "kc-1"})
        assert sso.post("/auth/backchannel-logout", data={}).status_code == 400
        token = self.logout_token(provider, sid="kc-1")
        twice = sso.post(
            "/auth/backchannel-logout",
            content=f"logout_token={token}&logout_token={token}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert twice.status_code == 400
        assert sso.get("/auth/session").json()["signed_in"] is True

    def test_without_single_sign_on_there_is_nothing_to_end(self, client) -> None:
        resp = client.post("/auth/backchannel-logout", data={"logout_token": "x"})
        assert resp.status_code == 404


class TestOnlyPeopleWithARole:
    """AGENTGOV_OIDC_REQUIRE_ROLE: people the provider signs in with no role are refused,
    unless they are given the person role (by the provider or in AgentGov)."""

    @staticmethod
    def client(settings: Settings, provider: FakeProvider, **overrides: Any) -> TestClient:
        settings = settings.with_overrides(**overrides)
        transport = httpx.MockTransport(provider.handle)
        runtime = Runtime(settings, oidc_http=httpx.Client(transport=transport))
        return TestClient(create_app(settings, runtime=runtime, background=False))

    def test_people_without_a_role_are_refused(self, sso_settings, provider) -> None:
        with self.client(sso_settings, provider, oidc_require_role=True) as client:
            assert error_code(sign_in(client, provider, roles=[])) == "no_role"
            assert client.get("/v1/me").status_code == 401
            signing_in = client.get("/v1/access", headers=ADMIN).json()["provider"]
            assert (signing_in["require_role"], signing_in["without_role"]) == (True, None)
            # With a role, as ever.
            assert sign_in(client, provider, roles=["agentgov-auditor"]).headers["location"] == (
                "/ui/"
            )
            assert client.get("/v1/me").json()["roles"] == ["auditor"]

    def test_the_person_role_lets_owners_and_sponsors_in(self, sso_settings, provider) -> None:
        with self.client(sso_settings, provider, oidc_require_role=True) as client:
            assert sign_in(client, provider, roles=["agentgov-person"]).headers["location"] == (
                "/ui/"
            )
            assert client.get("/v1/me").json()["roles"] == ["person"]
            # The person role adds nothing to a role they have.
            client.cookies.clear()
            sign_in(client, provider, roles=["agentgov-person", "agentgov-approver"])
            assert client.get("/v1/me").json()["roles"] == ["approver"]

    def test_given_in_agentgov(self, sso_settings, provider) -> None:
        with self.client(sso_settings, provider, oidc_require_role=True) as client:
            body = {"email": "alice@example.com", "role": "person", "reason": "owns agents"}
            resp = client.post("/v1/access/grants", json=body, headers=ADMIN)
            assert resp.status_code == 201, resp.text
            assert sign_in(client, provider, roles=[]).headers["location"] == "/ui/"
            assert client.get("/v1/me").json()["roles"] == ["person"]
            login = client.get("/v1/ledger", params={"type": "admin.login"}, headers=ADMIN)
            assert login.json()[0]["details"]["given_in_agentgov"] == ["person"]

    def test_mapped_from_a_group(self, sso_settings, provider) -> None:
        with self.client(
            sso_settings,
            provider,
            oidc_require_role=True,
            oidc_role_map="Agent owners=person,Platform team=admin",
        ) as client:
            sign_in(client, provider, roles=["Agent owners"])
            assert client.get("/v1/me").json()["roles"] == ["person"]
        with pytest.raises(ValueError, match="person"):
            Settings(oidc_role_map="Agent owners=owner").oidc_role_pairs()

    def test_sessions_without_a_role_end_once_one_is_required(self, sso_settings, provider) -> None:
        # While anyone may sign in, someone without a role does: their session has none.
        with self.client(sso_settings, provider) as anyone:
            sign_in(anyone, provider, sub="user-1", roles=[])
            assert anyone.get("/v1/me").json()["roles"] == ["person"]
            signing_in = anyone.get("/v1/access", headers=ADMIN).json()["provider"]
            assert (signing_in["require_role"], signing_in["without_role"]) == (False, "person")
            sign_in(
                anyone, provider, sub="user-2", email="bob@example.com", roles=["agentgov-person"]
            )
            bob = anyone.cookies.get("agentgov_session")
            anyone.cookies.clear()
            sign_in(anyone, provider, sub="user-1", roles=[])
            alice = anyone.cookies.get("agentgov_session")
        # Then only people with a role may: alice's session ends; bob was given his.
        with self.client(sso_settings, provider, oidc_require_role=True) as strict:
            strict.cookies.set("agentgov_session", alice)
            assert strict.get("/v1/me").status_code == 401
            strict.cookies.set("agentgov_session", bob)
            assert strict.get("/v1/me").json()["roles"] == ["person"]
