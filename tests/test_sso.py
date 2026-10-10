"""Administrator single sign-on against a fake OIDC provider."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
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

from agentgov import ids
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.identity.sso import display_name, roles_from_claims
from agentgov.models import AdminSession
from agentgov.runtime import Runtime
from tests.conftest import ADMIN

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
        base = {"iss": ISSUER, "sub": user.get("sub", "user-1"), "iat": now, "exp": now + 300}
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
        if request.url.path.endswith("/certs"):
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

    def test_bearer_tokens_still_work(self, sso) -> None:
        assert sso.get("/v1/me", headers=ADMIN).json()["via"] == "token"

    def test_disabled_without_a_client_secret(self, client) -> None:
        assert client.get("/auth/login", follow_redirects=False).status_code == 404
        assert client.get("/v1/info").json()["sso"]["enabled"] is False


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
