"""Identity assertions (ID-JAG) for MCP servers outside the gateway: AgentGov as the issuer
(agentgov.identity.assertions, agentgov.web.assertions)."""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from agentgov.config import Settings
from agentgov.identity import assertions
from agentgov.models import LedgerEntry
from agentgov.registry import agents, blueprints, features, toolservers
from agentgov.registry.errors import ValidationError
from agentgov.secops import ocsf
from agentgov.web import assertions as assertion_routes
from tests.conftest import ADMIN, requires_opa
from tests.test_opa import _decide

ISSUER = "http://localhost:8180/realms/agentgov"
JWKS_URL = "http://keycloak:8080/realms/agentgov/protocol/openid-connect/certs"
WIKI_AS = "https://id.wiki.example.com/realms/wiki"
WIKI = "https://wiki.example.com/mcp"


class FakeKeycloak:
    """Keycloak's signing key, and the tokens it gives agents."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "kc-1"
        self.fetches = 0

    def jwks(self, request: httpx.Request) -> httpx.Response:
        self.fetches += 1
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return httpx.Response(200, json={"keys": [{**public, "kid": self.kid, "use": "sig"}]})

    def checker(self) -> assertions.SubjectTokens:
        http = httpx.Client(transport=httpx.MockTransport(self.jwks))
        return assertions.SubjectTokens(ISSUER, JWKS_URL, "agentgov-gateway", http=http)

    def token(self, **claims: Any) -> str:
        now = int(time.time())
        body = {
            "iss": ISSUER,
            "aud": ["agentgov-gateway", "account"],
            "iat": now,
            "exp": now + 300,
            "jti": uuid.uuid4().hex,
            **claims,
        }
        body = {k: v for k, v in body.items() if v is not None}
        return jwt.encode(body, self.key, algorithm="RS256", headers={"kid": self.kid})


def agent_token(kc: FakeKeycloak, agent_id: str, client_id: str, **claims: Any) -> str:
    """The token an agent gets for itself (client credentials)."""
    own = {
        "sub": str(uuid.uuid4()),
        "azp": client_id,
        "agent_id": agent_id,
        "preferred_username": f"service-account-{client_id}",
    }
    return kc.token(**{**own, **claims})


def person_token(kc: FakeKeycloak, agent_id: str, client_id: str, **claims: Any) -> str:
    """A token an agent got for sam (exchanged)."""
    sams = {
        "sub": "u-sam",
        "azp": client_id,
        "agent_id": agent_id,
        "preferred_username": "sam",
        "email": "sam@example.com",
        "groups": ["/support"],
    }
    return kc.token(**{**sams, **claims})


def ask(**fields: Any) -> dict[str, list[str]]:
    base = {
        "grant_type": assertions.TOKEN_EXCHANGE,
        "requested_token_type": assertions.ID_JAG,
        "subject_token": "t",
        "subject_token_type": assertions.ACCESS_TOKEN,
        "audience": WIKI_AS,
    }
    return {k: [v] for k, v in {**base, **fields}.items() if v is not None}


# --------------------------------------------------------------------- the request


class TestTheRequest:
    def test_a_token_exchange_for_an_id_jag(self) -> None:
        req = assertions.parse(ask(resource=WIKI, scope="read"))
        assert (req.audience, req.resource, req.scope) == (WIKI_AS, WIKI, "read")
        assert assertions.form(urlencode({"a": "1", "b": ""}).encode()) == {"a": ["1"], "b": [""]}

    @pytest.mark.parametrize(
        ("fields", "error"),
        [
            ({"grant_type": "client_credentials"}, "unsupported_grant_type"),
            ({"requested_token_type": assertions.ACCESS_TOKEN}, "invalid_request"),
            ({"subject_token_type": "urn:ietf:params:oauth:token-type:saml2"}, "invalid_request"),
            ({"subject_token": None}, "invalid_request"),
            ({"audience": None}, "invalid_target"),
        ],
    )
    def test_what_it_refuses(self, fields: dict[str, Any], error: str) -> None:
        with pytest.raises(assertions.Refused) as refused:
            assertions.parse(ask(**fields))
        assert refused.value.error == error and refused.value.status == 400

    def test_one_audience_only(self) -> None:
        twice = {**ask(), "audience": [WIKI_AS, "https://other.example.com"]}
        with pytest.raises(assertions.Refused, match="one authorization server"):
            assertions.parse(twice)


# ------------------------------------------------------------- the token it brings


class TestTheTokenItBrings:
    def test_an_agents_token_for_the_gateway(self) -> None:
        kc = FakeKeycloak()
        claims = kc.checker().check(agent_token(kc, "agt_1", "agent-bot"), assertions.ACCESS_TOKEN)
        identity, person = assertions.caller(claims, assertions.ACCESS_TOKEN)
        assert identity == {"agent_id": "agt_1", "client_id": "agent-bot"}
        assert person is None  # its own service account

    def test_a_token_it_got_for_a_person(self) -> None:
        kc = FakeKeycloak()
        token = person_token(kc, "agt_1", "agent-bot")
        claims = kc.checker().check(token, assertions.ACCESS_TOKEN)
        identity, person = assertions.caller(claims, assertions.ACCESS_TOKEN)
        assert identity["client_id"] == "agent-bot"
        assert person is not None
        assert (person["id"], person["username"], person["via"]) == ("u-sam", "sam", "exchange")

    def test_an_id_token_names_the_agent_by_its_audience(self) -> None:
        kc = FakeKeycloak()
        token = kc.token(sub="u-sam", aud="agent-bot", typ="ID", preferred_username="sam")
        claims = kc.checker().check(token, assertions.ID_TOKEN)
        identity, _ = assertions.caller(claims, assertions.ID_TOKEN)
        assert identity == {"client_id": "agent-bot"}

    @pytest.mark.parametrize(
        "claims",
        [
            # An agent's token exchanged down to a resource server, which holds it: it names
            # the agent and its person, but it isn't an ID token.
            {"typ": "Bearer", "aud": "billing-api", "azp": "agent-bot", "agent_id": "agt_1"},
            {"aud": "agent-bot"},  # not marked as an ID token
            {"typ": "ID", "aud": ["agent-bot", "billing-api"]},
            {"typ": "ID", "aud": "billing-api", "azp": "agent-bot"},
        ],
    )
    def test_only_id_tokens_are_taken_as_such(self, claims: dict[str, Any]) -> None:
        kc = FakeKeycloak()
        token = kc.token(sub="u-sam", preferred_username="sam", **claims)
        with pytest.raises(assertions.Refused, match="isn't an ID token") as refused:
            kc.checker().check(token, assertions.ID_TOKEN)
        assert refused.value.error == "invalid_grant"

    @pytest.mark.parametrize(
        "claims",
        [
            {"aud": ["account"]},  # not for the gateway
            {"iss": "https://elsewhere.example.com"},
            {"exp": int(time.time()) - 600},
        ],
    )
    def test_tokens_it_refuses(self, claims: dict[str, Any]) -> None:
        kc = FakeKeycloak()
        with pytest.raises(assertions.Refused) as refused:
            kc.checker().check(agent_token(kc, "a", "agent-bot", **claims), assertions.ACCESS_TOKEN)
        assert refused.value.error == "invalid_grant"

    def test_keys_are_read_again_when_keycloak_rotates_them(self) -> None:
        kc = FakeKeycloak()
        checker = kc.checker()
        checker.check(agent_token(kc, "a", "agent-bot"), assertions.ACCESS_TOKEN)
        kc.key, kc.kid = rsa.generate_private_key(public_exponent=65537, key_size=2048), "kc-2"
        checker._fetched_at = 0  # the last fetch was long enough ago
        checker.check(agent_token(kc, "a", "agent-bot"), assertions.ACCESS_TOKEN)
        assert kc.fetches == 2
        forged = jwt.encode(
            {"iss": ISSUER, "sub": "x", "aud": "agentgov-gateway", "iat": 1, "exp": 2**31},
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            algorithm="RS256",
            headers={"kid": "kc-2"},
        )
        with pytest.raises(assertions.Refused, match="refused"):
            checker.check(forged, assertions.ACCESS_TOKEN)


# ------------------------------------------------------------------------ the ID-JAG


def test_the_assertion() -> None:
    key = assertions.signing_key("service-token")
    assert key is not None and assertions.signing_key(None) is None
    token, claims = assertions.issue(
        key,
        issuer="https://agentgov.example.com",
        subject="u-sam",
        audience=WIKI_AS,
        client_id="agentgov-agents",
        resource=WIKI,
        actor="agent-bot",
        scope="read",
        email="sam@example.com",
        lifetime=900,  # at most five minutes
        now=1_000,
    )
    header = jwt.get_unverified_header(token)
    assert header["typ"] == "oauth-id-jag+jwt" and header["alg"] == "ES256"
    published = assertions.jwks(key)["keys"][0]
    assert header["kid"] == published["kid"]
    checked = jwt.decode(
        token,
        jwt.PyJWK.from_dict(published).key,
        algorithms=["ES256"],
        audience=WIKI_AS,
        options={"verify_exp": False},
    )
    assert checked == claims
    assert claims["exp"] - claims["iat"] == 300
    assert (claims["sub"], claims["client_id"], claims["resource"]) == (
        "u-sam",
        "agentgov-agents",
        WIKI,
    )
    assert claims["act"] == {"sub": "agent-bot"} and claims["email"] == "sam@example.com"
    answer = assertions.response(token, claims)
    assert answer["issued_token_type"] == assertions.ID_JAG and answer["token_type"] == "N_A"
    assert answer["expires_in"] == 300 and answer["scope"] == "read"
    # Apart from the key delegations are signed with.
    from agentgov.identity import chains

    delegations = chains.keys("service-token")
    assert delegations is not None and delegations.kid != published["kid"]


def test_the_metadata() -> None:
    meta = assertions.metadata("https://agentgov.example.com")
    assert meta["token_endpoint"] == "https://agentgov.example.com/oauth2/token"
    assert meta["jwks_uri"] == "https://agentgov.example.com/oauth2/jwks"
    assert meta["grant_types_supported"] == [assertions.TOKEN_EXCHANGE]


# ------------------------------------------------------------- servers outside it


class TestServersOutsideTheGateway:
    def test_an_authorization_server_is_for_servers_outside_the_gateway(self, rt) -> None:
        with rt.db.session() as s:
            data = {"name": "wiki", "url": WIKI, "authorization_server": WIKI_AS}
            with pytest.raises(ValidationError, match="outside the gateway"):
                toolservers.create(s, data, actor="t", approve=True)
            wiki = toolservers.create(s, {**data, "gateway": False}, actor="t", approve=True)
            view = toolservers.to_dict(wiki)
            assert view["authorization_server"] == WIKI_AS and view["oauth_client_id"] is None
            with pytest.raises(ValidationError, match="needs its url"):
                toolservers.update(s, wiki, {"url": ""}, actor="t")

    def test_a_client_id_is_the_client_at_its_authorization_server(self, rt) -> None:
        with rt.db.session() as s:
            data = {"name": "crm", "url": "http://crm/mcp", "oauth_client_id": "x"}
            with pytest.raises(ValidationError, match="authorization_server"):
                toolservers.create(s, data, actor="t", approve=True)
            with pytest.raises(ValidationError, match="its issuer"):
                toolservers.create(
                    s,
                    {"name": "x", "url": WIKI, "gateway": False, "authorization_server": "id"},
                    actor="t",
                    approve=True,
                )

    def test_the_feature_needs_its_settings(self) -> None:
        settings = Settings()
        assert "AGENTGOV_SERVICE_TOKEN" in (
            features.unmet("identity-assertions", "on", settings) or ""
        )
        ready = dataclasses.replace(
            settings,
            service_token="t",
            keycloak_issuer=ISSUER,
            keycloak_jwks_url=JWKS_URL,
            opa_url="http://opa:8181",
        )
        assert features.unmet("identity-assertions", "on", ready) is None


# ---------------------------------------------------------------- the token endpoint


def _seed(rt: Any, settings: Settings) -> tuple[str, str]:
    """A wiki outside the gateway, and a crm on it; bot may use the wiki, helper may not."""
    with rt.db.session() as s:
        blueprints.create(
            s,
            {
                "name": "support",
                "require_sponsor": False,
                "permissions": [
                    {"server": "crm", "tools": ["*"]},
                    {"server": "wiki", "tools": ["search"]},
                ],
            },
            actor="t",
        )
        blueprints.create(
            s,
            {
                "name": "crm-only",
                "require_sponsor": False,
                "permissions": [{"server": "crm", "tools": ["*"]}],
            },
            actor="t",
        )
        toolservers.create(s, {"name": "crm", "url": "http://crm/mcp"}, actor="t", approve=True)
        toolservers.create(
            s,
            {
                "name": "wiki",
                "url": WIKI,
                "gateway": False,
                "authorization_server": WIKI_AS,
                "oauth_client_id": "agentgov-agents",
            },
            actor="t",
            approve=True,
        )
        bot = agents.register(
            s, settings, {"name": "bot", "blueprint": "support"}, actor="t", approve=True
        )
        helper = agents.register(
            s, settings, {"name": "helper", "blueprint": "crm-only"}, actor="t", approve=True
        )
        return bot.id, helper.id


@requires_opa
class TestTheTokenEndpoint:
    def test_assertions_with_the_real_policies(
        self, client, settings, tmp_path: Path, monkeypatch
    ) -> None:
        app_rt = client.app.state.rt
        bot, helper = _seed(app_rt, settings)
        kc = FakeKeycloak()

        def opa_post(url: str, *, json: dict[str, Any], **kw: Any) -> httpx.Response:
            assert url.endswith("/v1/data/agentgov/idjag/decision")
            return httpx.Response(
                200,
                json={
                    "result": _decide(
                        app_rt, tmp_path, json["input"], "data.agentgov.idjag.decision"
                    )
                },
            )

        monkeypatch.setattr(assertion_routes.httpx, "post", opa_post)
        app_rt.settings = dataclasses.replace(
            app_rt.settings,
            opa_url="http://opa:8181",
            service_token="service-token",
            keycloak_issuer=ISSUER,
            keycloak_jwks_url=JWKS_URL,
            public_url="https://agentgov.example.com",
        )
        app_rt.subject_tokens = kc.checker()
        form = {"Content-Type": "application/x-www-form-urlencoded"}

        def exchange(token: str, **fields: Any) -> httpx.Response:
            body = {k: v[0] for k, v in ask(subject_token=token, **fields).items()}
            return client.post("/oauth2/token", content=urlencode(body), headers=form)

        sams = person_token(kc, bot, "agent-bot")
        # Off by default: no assertions, no metadata; the keys are public whatever.
        assert exchange(sams).status_code == 404
        assert client.get("/.well-known/oauth-authorization-server").status_code == 404
        keys = client.get("/oauth2/jwks").json()["keys"]
        assert len(keys) == 1 and keys[0]["alg"] == "ES256"
        client.put("/v1/features/identity-assertions", json={"mode": "on"}, headers=ADMIN)
        meta = client.get("/.well-known/oauth-authorization-server").json()
        assert meta["issuer"] == "https://agentgov.example.com"

        # bot, acting for sam, gets one for the wiki.
        resp = exchange(sams, resource=WIKI, scope="search")
        assert resp.status_code == 200, resp.text
        assert resp.headers["cache-control"] == "no-store"
        answer = resp.json()
        assert answer["issued_token_type"] == assertions.ID_JAG and answer["expires_in"] == 300
        claims = jwt.decode(
            answer["access_token"],
            jwt.PyJWK.from_dict(keys[0]).key,
            algorithms=["ES256"],
            audience=WIKI_AS,
        )
        assert claims["iss"] == "https://agentgov.example.com" and claims["sub"] == "u-sam"
        assert claims["client_id"] == "agentgov-agents" and claims["resource"] == WIKI
        assert claims["act"] == {"sub": "agent-bot"} and claims["scope"] == "search"
        # On its own, the agent is the subject, and its own client ID the client there when
        # the server names none.
        with app_rt.db.session() as s:
            toolservers.update(s, toolservers.get(s, "wiki"), {"oauth_client_id": None}, actor="t")
        own = exchange(agent_token(kc, bot, "agent-bot", sub="sa-bot")).json()
        alone = jwt.decode(own["access_token"], options={"verify_signature": False})
        assert (alone["sub"], alone["client_id"]) == ("sa-bot", "agent-bot") and "act" not in alone

        # helper isn't granted the wiki: refused, and why.
        refused = exchange(agent_token(kc, helper, "agent-helper"))
        assert refused.status_code == 400
        assert refused.json() == {
            "error": "invalid_target",
            "error_description": "No tool of wiki is granted to agent helper",
        }
        # An authorization server no registered server takes tokens from.
        unknown = exchange(sams, audience="https://id.elsewhere.example.com")
        assert unknown.json()["error"] == "invalid_target"
        # A token that isn't Keycloak's.
        assert exchange("not-a-jwt").json()["error"] == "invalid_grant"
        # Not a form.
        not_form = client.post("/oauth2/token", json={"grant_type": "x"})
        assert not_form.json()["error"] == "invalid_request"

        # Monitored, least privilege lets it through, and says so.
        client.put("/v1/features/least-privilege", json={"mode": "monitor"}, headers=ADMIN)
        assert exchange(agent_token(kc, helper, "agent-helper")).status_code == 200

        with app_rt.db.session() as s:
            entries = list(
                s.scalars(
                    select(LedgerEntry)
                    .where(LedgerEntry.type == "decision.assertion")
                    .order_by(LedgerEntry.seq)
                )
            )
        assert [(e.agent_name, e.decision) for e in entries] == [
            ("bot", "allow"),
            ("bot", "allow"),
            ("helper", "deny"),
            ("helper", "allow"),
        ]
        first = entries[0]
        assert first.on_behalf_of == "sam" and first.resource == "wiki"
        assert first.details["audience"] == WIKI_AS and first.details["jti"] == claims["jti"]
        assert entries[2].reason == "No tool of wiki is granted to agent helper"
        # To the security team's tools: an access decision on the server, refused.
        event = ocsf.event(entries[2])
        assert (event["class_uid"], event["activity_name"]) == (6003, "Identity assertion")
        assert event["resources"] == [{"name": "wiki", "type": "MCP Server"}]
        assert event["disposition"] == "Blocked"
        assert entries[3].details["monitored"] == [
            "least-privilege: No tool of wiki is granted to agent helper"
        ]


# ------------------------------------------------- an authorization server that takes them

KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.8.0"


def _keycloak_ready() -> bool:
    if shutil.which("docker") is None or os.environ.get("AGENTGOV_TEST_POSTGRES_URL"):
        return False  # (it doesn't depend on the database: once is enough)
    probe = subprocess.run(
        ["docker", "image", "inspect", KEYCLOAK_IMAGE], capture_output=True, check=False
    )
    return probe.returncode == 0


@pytest.fixture
def wiki_keycloak() -> Iterator[str]:
    """Keycloak 26.8, which takes ID-JAGs as an experimental feature, as the wiki's
    authorization server: its base URL."""
    # Its scratch files and development database in memory: nothing to keep, and a host
    # short of disk space still runs it.
    started = subprocess.run(
        ["docker", "run", "-d", "--rm", "-p", "127.0.0.1::8080",
         "--tmpfs", "/tmp", "--tmpfs", "/opt/keycloak/data:uid=1000",
         "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=admin",
         KEYCLOAK_IMAGE, "start-dev", "--features=identity-assertion-jwt"],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    container = started.stdout.strip()
    try:
        port = (
            subprocess.run(
                ["docker", "port", container, "8080/tcp"],
                capture_output=True,
                text=True,
                check=True,
            )
            .stdout.split(":")[-1]
            .strip()
        )
        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"{base}/realms/master", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        else:
            pytest.fail("Keycloak didn't start")
        yield base
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=False)


@pytest.mark.skipif(not _keycloak_ready(), reason=f"docker or {KEYCLOAK_IMAGE} not available")
def test_keycloak_trades_agentgovs_assertions_for_access_tokens(wiki_keycloak: str) -> None:
    """The receiving side, as docs/acting-for-people.md sets it up: an identity provider
    for AgentGov's issuer that takes JWT authorization grants, a client that may use them,
    and the person linked to it."""
    base, issuer = wiki_keycloak, "https://agentgov.example.com"
    key = assertions.signing_key("service-token")
    assert key is not None
    kid = assertions.jwks(key)["keys"][0]["kid"]
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    http = httpx.Client(timeout=30)
    admin = http.post(
        f"{base}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli", "username": "admin",
              "password": "admin"},
    ).json()["access_token"]  # fmt: skip
    headers = {"Authorization": f"Bearer {admin}"}
    http.post(f"{base}/admin/realms", headers=headers, json={"realm": "wiki", "enabled": True})
    realm = f"{base}/admin/realms/wiki"
    provider = {
        "alias": "agentgov",
        "providerId": "jwt-authorization-grant",
        "enabled": True,
        "config": {
            "issuer": issuer,
            "useJwksUrl": "false",
            "publicKeySignatureVerifier": pem.decode(),
            "publicKeySignatureVerifierKeyId": kid,
            "validateSignature": "true",
            "jwtAuthorizationGrantEnabled": "true",
            "jwtAuthorizationGrantAssertionReuseAllowed": "false",
            "jwtAuthorizationGrantMaxAllowedAssertionExpiration": "300",
        },
    }
    assert (
        http.post(
            f"{realm}/identity-provider/instances", headers=headers, json=provider
        ).status_code
        == 201
    )
    client = {
        "clientId": "agentgov-agents",
        "secret": "wiki-secret",
        "publicClient": False,
        "serviceAccountsEnabled": False,
        "standardFlowEnabled": False,
        "attributes": {
            "oauth2.jwt.authorization.grant.enabled": "true",
            "oauth2.jwt.authorization.grant.idp": "agentgov",
        },
    }
    assert http.post(f"{realm}/clients", headers=headers, json=client).status_code == 201
    person = {"username": "sam", "enabled": True, "email": "sam@example.com"}
    assert http.post(f"{realm}/users", headers=headers, json=person).status_code == 201
    [sam] = http.get(f"{realm}/users", headers=headers, params={"username": "sam"}).json()
    link = {"identityProvider": "agentgov", "userId": "u-sam", "userName": "sam"}
    linked = http.post(
        f"{realm}/users/{sam['id']}/federated-identity/agentgov", headers=headers, json=link
    )
    assert linked.status_code == 204

    def assertion(**changes: Any) -> str:
        fields = {
            "issuer": issuer,
            "subject": "u-sam",
            "audience": f"{base}/realms/wiki",
            "client_id": "agentgov-agents",
            "resource": WIKI,
            "actor": "agent-bot",
            "email": "sam@example.com",
            **changes,
        }
        return assertions.issue(key, **fields)[0]

    def trade(token: str, client_id: str = "agentgov-agents") -> httpx.Response:
        return http.post(
            f"{base}/realms/wiki/protocol/openid-connect/token",
            data={"grant_type": assertions.JWT_BEARER, "assertion": token},
            auth=(client_id, "wiki-secret"),
        )

    given = assertion()
    traded = trade(given)
    assert traded.status_code == 200, traded.text
    access = jwt.decode(traded.json()["access_token"], options={"verify_signature": False})
    assert access["sub"] == sam["id"] and access["preferred_username"] == "sam"
    assert access["azp"] == "agentgov-agents"
    # Each assertion once only; and only for the client it names, for the person linked.
    assert trade(given).json()["error"] == "invalid_grant"
    assert trade(assertion(client_id="someone-else")).status_code == 400
    assert trade(assertion(subject="u-nobody")).status_code == 400
    assert trade(assertion(audience=f"{base}/realms/other")).status_code == 400
