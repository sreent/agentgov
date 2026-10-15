"""Single sign-on with identity providers other than Keycloak: endpoints from the provider's
discovery document, roles from its claims or given in AgentGov, and who may sign in."""

from __future__ import annotations

import base64
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from starlette.testclient import TestClient

from agentgov import cli
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.identity.sso import (
    DISCOVERY_PATH,
    DISCOVERY_SECONDS,
    roles_from_claims,
    verified_email,
)
from agentgov.runtime import Runtime
from tests.conftest import ADMIN
from tests.test_cli import _Shared, runner
from tests.test_sso import (
    CLIENT_ID,
    CLIENT_SECRET,
    CSRF,
    FakeProvider,
    _feature,
    at_the_cli,
    cli_sign_in,
    error_code,
    sign_in,
)

OKTA = "https://example.okta.test/oauth2/default"
GROUP_ID = "8f0c2d1e-0000-4000-8000-000000000001"
TENANT = "3f2a1b4c-0000-4000-8000-00000000abcd"


class DiscoveredProvider(FakeProvider):
    """A provider like Okta: its endpoints in its discovery document, groups in its ID
    tokens, and an access token whose subject is the person's login, not the ID token's."""

    def __init__(
        self,
        issuer: str = OKTA,
        *,
        auth_methods: list[str] | None = None,
        end_session: bool = True,
    ) -> None:
        super().__init__()
        self.issuer = issuer
        base = issuer.rstrip("/")
        self.document: dict[str, Any] = {
            "issuer": issuer,
            "authorization_endpoint": f"{base}/v1/authorize",
            "token_endpoint": f"{base}/v1/token",
            "jwks_uri": f"{base}/v1/keys",
        }
        if end_session:
            self.document["end_session_endpoint"] = f"{base}/v1/logout"
        if auth_methods is not None:
            self.document["token_endpoint_auth_methods_supported"] = auth_methods
        self.discovery_status = 200
        self.discovery_reads = 0
        self.token_requests: list[dict[str, Any]] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(DISCOVERY_PATH):
            self.discovery_reads += 1
            if self.discovery_status != 200:
                return httpx.Response(self.discovery_status)
            return httpx.Response(200, json=self.document)
        if request.url.path.endswith("/token"):
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append(
                {"authorization": request.headers.get("authorization"), "form": dict(form)}
            )
            if "client_secret" in form:
                # client_secret_post: the parent checks the credentials as a Basic header.
                creds = f"{form.pop('client_id')}:{form.pop('client_secret')}".encode()
                headers = {"authorization": "Basic " + base64.b64encode(creds).decode()}
                body = "&".join(f"{k}={v}" for k, v in form.items())
                request = httpx.Request("POST", request.url, headers=headers, content=body)
        return super().handle(request)


def _client(tmp_path: Path, provider: FakeProvider, **settings: Any) -> TestClient:
    values = {
        "database_url": f"sqlite:///{tmp_path / 'agentgov.db'}",
        "admin_token": "test-admin",
        "service_token": "test-service",
        "posture_interval_seconds": 0,
        "oidc_issuer": provider.issuer,
        "oidc_client_secret": CLIENT_SECRET,
        **settings,
    }
    config = Settings(**values)
    config.validate()
    runtime = Runtime(
        config, oidc_http=httpx.Client(transport=httpx.MockTransport(provider.handle))
    )
    return TestClient(create_app(config, runtime=runtime, background=False))


@pytest.fixture
def okta() -> DiscoveredProvider:
    return DiscoveredProvider()


@pytest.fixture
def at_okta(tmp_path: Path, okta: DiscoveredProvider) -> Iterator[TestClient]:
    with _client(tmp_path, okta) as client:
        yield client


def groups(*names: str) -> dict[str, Any]:
    """An Okta-style user: groups in the ID token, and the login as the access token's
    subject."""
    return {"id_claims": {"groups": list(names)}, "access_claims": {"sub": "alice@example.com"}}


class TestDiscovery:
    def test_the_issuer_is_all_it_takes(self, at_okta, okta) -> None:
        start = at_okta.get("/auth/login", follow_redirects=False)
        assert start.headers["location"].startswith(f"{OKTA}/v1/authorize?")
        resp = sign_in(at_okta, okta, **groups("agentgov-secops", "Everyone"))
        assert resp.headers["location"] == "/ui/"
        me = at_okta.get("/v1/me").json()
        assert (me["name"], me["roles"]) == ("alice@example.com", ["secops"])
        # The provider's logout endpoint, from its document.
        out = at_okta.post("/auth/logout", headers=CSRF).json()
        assert out["logout_url"].startswith(f"{OKTA}/v1/logout?")
        # Read once, and kept.
        assert okta.discovery_reads == 1
        # Basic authentication, the default.
        assert okta.token_requests[0]["authorization"].startswith("Basic ")
        provider = at_okta.get("/v1/access", headers=ADMIN).json()["provider"]
        assert provider == {
            "kind": "oidc",
            "issuer": OKTA,
            "client_id": CLIENT_ID,
            "discovered": True,
            "roles_claims": ["groups"],
            "role_map": [],
            "role_prefix": "agentgov-",
            "allowed_domains": [],
            # People without a role sign in to see what is sent to them.
            "require_role": False,
            "without_role": "person",
            "problem": None,
        }

    def test_an_issuer_with_a_trailing_slash(self, tmp_path) -> None:
        # Auth0's and JumpCloud's issuers end in a slash, which is often left off.
        provider = DiscoveredProvider("https://tenant.auth0.test/")
        with _client(tmp_path, provider, oidc_issuer="https://tenant.auth0.test") as client:
            resp = sign_in(client, provider, **groups("agentgov-auditor"))
            assert resp.headers["location"] == "/ui/"
            assert client.get("/v1/me").json()["roles"] == ["auditor"]

    def test_a_document_for_another_issuer_is_refused(self, at_okta, okta) -> None:
        okta.document["issuer"] = "https://evil.test/oauth2/default"
        start = at_okta.get("/auth/login", follow_redirects=False)
        assert error_code(start) == "provider"
        problem = at_okta.get("/v1/access", headers=ADMIN).json()["provider"]["problem"]
        assert "is for issuer 'https://evil.test/oauth2/default'" in problem
        listing = _cli(at_okta, ["access", "list"])
        assert "note: people can't sign in: the discovery document" in listing.output

    def test_an_unreachable_provider(self, at_okta, okta) -> None:
        okta.discovery_status = 503
        assert error_code(at_okta.get("/auth/login", follow_redirects=False)) == "provider"
        # The CLI's sign-in hears of it at its loopback listener.
        _, back = cli_sign_in_failed(at_okta)
        assert at_the_cli(back) == {"error": "provider"}
        # Once read, the document outlives a short outage.
        okta.discovery_status = 200
        assert sign_in(at_okta, okta, **groups("agentgov-admin")).headers["location"] == "/ui/"
        okta.discovery_status = 503
        reads = okta.discovery_reads
        at_okta.app.state.rt.sso._metadata_at = time.monotonic() - DISCOVERY_SECONDS - 1
        assert sign_in(at_okta, okta, **groups("agentgov-admin")).headers["location"] == "/ui/"
        assert okta.discovery_reads == reads + 1  # it tried, an hour later

    def test_providers_that_take_only_client_secret_post(self, tmp_path) -> None:
        provider = DiscoveredProvider(auth_methods=["client_secret_post"])
        with _client(tmp_path, provider) as client:
            assert sign_in(client, provider, **groups("agentgov-admin")).headers["location"] == (
                "/ui/"
            )
        sent = provider.token_requests[0]
        assert sent["authorization"] is None
        assert (sent["form"]["client_id"], sent["form"]["client_secret"]) == (
            CLIENT_ID,
            CLIENT_SECRET,
        )

    def test_the_client_authentication_can_be_chosen(self, tmp_path) -> None:
        provider = DiscoveredProvider(auth_methods=["client_secret_basic", "client_secret_post"])
        with _client(tmp_path, provider, oidc_client_auth="client_secret_post") as client:
            sign_in(client, provider, **groups("agentgov-admin"))
        assert provider.token_requests[0]["form"]["client_secret"] == CLIENT_SECRET
        with pytest.raises(ValueError, match="AGENTGOV_OIDC_CLIENT_AUTH"):
            Settings(oidc_client_auth="private_key_jwt").validate()

    def test_without_a_logout_endpoint_only_agentgov_signs_out(self, tmp_path) -> None:
        # Google's and Dex's documents name none.
        provider = DiscoveredProvider(end_session=False)
        with _client(tmp_path, provider) as client:
            sign_in(client, provider, **groups("agentgov-admin"))
            assert client.post("/auth/logout", headers=CSRF).json() == {"logout_url": None}
            assert client.get("/v1/me").status_code == 401

    def test_roles_come_from_the_id_token(self, at_okta, okta) -> None:
        # Not from an access token about someone else (Okta's names the login), which
        # isn't a reason to refuse the sign-in either.
        _feature(at_okta, "issues", "off")
        resp = sign_in(at_okta, okta, roles=["agentgov-admin"], **groups())
        assert error_code(resp) == "no_role"
        # People without a role sign in to see their issues.
        _feature(at_okta, "issues", "on")
        assert sign_in(at_okta, okta, **groups()).headers["location"] == "/ui/"
        assert at_okta.get("/v1/me").json()["roles"] == ["person"]

    def test_endpoints_set_by_hand_need_no_document(self, tmp_path, okta) -> None:
        okta.discovery_status = 404
        base = OKTA
        with _client(
            tmp_path,
            okta,
            oidc_authorization_endpoint=f"{base}/v1/authorize",
            oidc_token_endpoint=f"{base}/v1/token",
            oidc_jwks_url=f"{base}/v1/keys",
        ) as client:
            assert sign_in(client, okta, **groups("agentgov-admin")).headers["location"] == "/ui/"
            # Without one set, no provider logout.
            assert client.post("/auth/logout", headers=CSRF).json() == {"logout_url": None}
        assert okta.discovery_reads == 0


def cli_sign_in_failed(client: TestClient) -> tuple[str, httpx.Response]:
    """`agentgov login` against a provider that can't be read: the browser goes straight
    back to the CLI."""
    import hashlib
    import secrets

    from tests.test_sso import CLI_PORT, _b64url

    verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    params = {"cli_port": CLI_PORT, "cli_challenge": challenge}
    return verifier, client.get("/auth/login", params=params, follow_redirects=False)


def _cli(client: TestClient, args: list[str]) -> Any:
    original = cli._client
    cli._client = lambda: _Shared(client, "test-admin")  # type: ignore[assignment]
    try:
        return runner.invoke(cli.app, args)
    finally:
        cli._client = original  # type: ignore[assignment]


class TestRoleMap:
    def test_mapped_values_grant_roles_and_nothing_else(self, tmp_path, okta) -> None:
        role_map = f"{GROUP_ID}=admin, Security Operations=secops"
        with _client(tmp_path, okta, oidc_role_map=role_map) as client:
            sign_in(client, okta, **groups(GROUP_ID, "agentgov-auditor"))
            assert client.get("/v1/me").json()["roles"] == ["admin"]
            sign_in(client, okta, sub="user-2", **groups("Security Operations"))
            assert client.get("/v1/me").json()["roles"] == ["secops"]
            provider = client.get("/v1/access", headers=ADMIN).json()["provider"]
            assert provider["role_map"] == [
                {"value": GROUP_ID, "role": "admin"},
                {"value": "Security Operations", "role": "secops"},
            ]
            assert provider["role_prefix"] is None

    def test_claims_of_every_shape(self) -> None:
        claims = {
            "https://agentgov.test/roles": ["agentgov-approver"],
            "cognito:groups": ["agentgov-auditor"],
            "realm_access": {"roles": ["agentgov-admin"]},
            "scope_roles": "agentgov-registrar agentgov-secops",
            "team": "Security Operations",
        }
        prefix = "agentgov-"
        assert roles_from_claims(claims, "https://agentgov.test/roles", prefix) == ["approver"]
        assert roles_from_claims(claims, "cognito:groups", prefix) == ["auditor"]
        assert roles_from_claims(claims, "realm_access.roles", prefix) == ["admin"]
        assert roles_from_claims(claims, "scope_roles", prefix) == ["secops", "registrar"]
        both = ["cognito:groups", "realm_access.roles"]
        assert roles_from_claims(claims, both, prefix) == ["admin", "auditor"]
        mapped = {"Security Operations": {"secops"}}
        assert roles_from_claims(claims, "team", prefix, mapped) == ["secops"]
        # A group named after a role grants nothing without the prefix, or with a map.
        assert roles_from_claims({"groups": ["admin"]}, "groups", prefix) == []
        assert roles_from_claims(claims, "cognito:groups", prefix, mapped) == []

    @pytest.mark.parametrize("value", ["admins=root", "no-equals-sign", "=admin"])
    def test_the_map_is_checked(self, value) -> None:
        with pytest.raises(ValueError, match="AGENTGOV_OIDC_ROLE_MAP"):
            Settings(oidc_role_map=value).validate()

    def test_several_claims_and_the_default_per_provider(self) -> None:
        assert Settings().oidc_roles_claims() == ["realm_access.roles"]
        entra = Settings(oidc_issuer=f"https://login.microsoftonline.com/{TENANT}/v2.0")
        assert entra.oidc_roles_claims() == ["roles"]
        assert Settings(oidc_issuer=OKTA).oidc_roles_claims() == ["groups"]
        keycloak = Settings(oidc_issuer="https://sso.example.test/realms/staff")
        assert (keycloak.oidc_provider, keycloak.oidc_roles_claims()) == (
            "keycloak",
            ["realm_access.roles"],
        )
        mixed = Settings(oidc_issuer=OKTA, oidc_roles_claim="groups, roles")
        assert mixed.oidc_roles_claims() == ["groups", "roles"]


GOOGLE = "https://accounts.google.com"


class TestAllowedDomains:
    def test_google_needs_them(self) -> None:
        with pytest.raises(ValueError, match="AGENTGOV_OIDC_ALLOWED_DOMAINS"):
            Settings(oidc_issuer=GOOGLE, oidc_client_secret="s").validate()
        with pytest.raises(ValueError, match="is not a domain"):
            Settings(oidc_allowed_domains="example.com, not a domain").validate()

    def test_google_accounts_of_the_organisation(self, tmp_path) -> None:
        google = DiscoveredProvider(GOOGLE, end_session=False)
        with _client(tmp_path, google, oidc_allowed_domains="Example.com") as client:
            resp = sign_in(client, google, id_claims={"hd": "example.com"})
            assert resp.headers["location"] == "/ui/"
            # A personal Google account has no hosted domain.
            assert error_code(sign_in(client, google, id_claims={"email": "a@gmail.com"})) == (
                "domain"
            )
            other = {"hd": "other.test", "email": "eve@other.test"}
            assert error_code(sign_in(client, google, id_claims=other)) == "domain"

    def test_other_providers_check_the_verified_email(self, tmp_path, okta) -> None:
        with _client(tmp_path, okta, oidc_allowed_domains="example.com") as client:
            assert sign_in(client, okta, **groups("agentgov-admin")).headers["location"] == "/ui/"
            outsider = {"id_claims": {"email": "eve@other.test", "groups": ["agentgov-admin"]}}
            assert error_code(sign_in(client, okta, **outsider)) == "domain"
            unverified = {"email_verified": False, "groups": ["agentgov-admin"]}
            assert error_code(sign_in(client, okta, id_claims=unverified)) == "domain"


def grant(client: TestClient, email: str, role: str, **extra: Any) -> httpx.Response:
    return client.post(
        "/v1/access/grants", json={"email": email, "role": role, **extra}, headers=ADMIN
    )


class TestGivenRoles:
    def test_a_role_given_here_applies_at_sign_in(self, tmp_path) -> None:
        google = DiscoveredProvider(GOOGLE, end_session=False)
        with _client(tmp_path, google, oidc_allowed_domains="example.com") as client:
            given = grant(client, "Alice@Example.com", "auditor", reason="first auditor")
            assert given.status_code == 201, given.text
            assert given.json()["email"] == "alice@example.com"
            assert given.json()["granted_at"]
            resp = sign_in(client, google, id_claims={"hd": "example.com"})
            assert resp.headers["location"] == "/ui/"
            assert client.get("/v1/me").json()["roles"] == ["auditor"]
            ledger = client.get("/v1/ledger", headers=ADMIN).json()
            login = next(e for e in ledger if e["type"] == "admin.login")
            assert login["details"]["given_in_agentgov"] == ["auditor"]
            granted = next(e for e in ledger if e["type"] == "access.role_granted")
            assert (granted["actor"], granted["reason"]) == ("admin:bootstrap", "first auditor")
            view = client.get("/v1/access", headers=ADMIN).json()
            assert [(g["email"], g["role"]) for g in view["grants"]] == [
                ("alice@example.com", "auditor")
            ]

    def test_they_add_to_the_providers(self, at_okta, okta) -> None:
        grant(at_okta, "alice@example.com", "auditor").raise_for_status()
        sign_in(at_okta, okta, **groups("agentgov-approver"))
        assert at_okta.get("/v1/me").json()["roles"] == ["approver", "auditor"]

    def test_only_an_email_the_provider_vouches_for(self, at_okta, okta) -> None:
        _feature(at_okta, "issues", "off")
        grant(at_okta, "alice@example.com", "admin").raise_for_status()
        resp = sign_in(at_okta, okta, id_claims={"email_verified": False})
        assert error_code(resp) == "no_role"

    def test_taking_one_away_ends_their_sessions(self, at_okta, okta) -> None:
        grant(at_okta, "alice@example.com", "approver").raise_for_status()
        sign_in(at_okta, okta, **groups())
        assert at_okta.get("/v1/me").json()["roles"] == ["approver"]
        out = at_okta.delete("/v1/access/grants/alice%40example.com/approver", headers=ADMIN)
        assert out.json() == {"ended": 1}
        assert at_okta.get("/v1/me").status_code == 401
        ledger = at_okta.get("/v1/ledger", headers=ADMIN).json()
        assert {"access.role_revoked", "admin.session_ended"} <= {e["type"] for e in ledger}

    def test_only_admins_and_checked(self, at_okta, okta) -> None:
        assert grant(at_okta, "not-an-email", "admin").status_code == 422
        assert grant(at_okta, "bob@example.com", "root").status_code == 422
        assert grant(at_okta, "bob@example.com", "admin", scope="emea").status_code == 422
        grant(at_okta, "bob@example.com", "admin").raise_for_status()
        assert grant(at_okta, "bob@example.com", "admin").status_code == 409
        missing = at_okta.delete("/v1/access/grants/carol%40example.com/admin", headers=ADMIN)
        assert missing.status_code == 404
        sign_in(at_okta, okta, **groups("agentgov-approver"))
        body = {"email": "mallory@example.com", "role": "admin"}
        refused = at_okta.post("/v1/access/grants", json=body, headers=CSRF)
        assert refused.status_code == 403

    def test_the_cli(self, at_okta) -> None:
        out = _cli(at_okta, ["access", "grant", "bob@example.com", "auditor", "--reason", "audit"])
        assert out.output.strip() == "role/auditor for bob@example.com: given", out.output
        listing = _cli(at_okta, ["access", "grants"]).output
        assert "bob@example.com" in listing and "admin:bootstrap" in listing
        out = _cli(at_okta, ["access", "revoke", "bob@example.com", "auditor"])
        assert (
            out.output.strip() == "role/auditor for bob@example.com: taken away (0 sessions ended)"
        )


ENTRA = f"https://login.microsoftonline.com/{TENANT}/v2.0"


class TestEntra:
    def test_people_without_a_role_sign_in(self, tmp_path) -> None:
        # Microsoft Entra ID's access token is for Microsoft Graph: AgentGov can't read it,
        # and its ID token has no email_verified.
        provider = FakeProvider()
        provider.issuer = ENTRA
        with _client(tmp_path, provider) as client:
            resp = sign_in(
                client,
                provider,
                id_claims={"email_verified": None, "preferred_username": "alice@example.com"},
                access_claims={"aud": "00000003-0000-0000-c000-000000000000"},
            )
            assert resp.headers["location"] == "/ui/"
            me = client.get("/v1/me").json()
            assert (me["name"], me["roles"]) == ("alice@example.com", ["person"])

    def test_app_roles_come_from_the_id_token(self, tmp_path) -> None:
        provider = FakeProvider()
        provider.issuer = ENTRA
        with _client(tmp_path, provider) as client:
            sign_in(client, provider, id_claims={"roles": ["agentgov-admin"]})
            assert client.get("/v1/me").json()["roles"] == ["admin"]

    def test_which_email_address_counts(self) -> None:
        base = {"sub": "s", "preferred_username": "alice@contoso.test"}
        # Entra: the tenant's administrators set both.
        assert verified_email({**base, "email": "a@example.com"}, "entra") == "a@example.com"
        # Unless the tenant says the address's domain isn't one it verified.
        no_domain = {**base, "email": "a@example.com", "xms_edov": False}
        assert verified_email(no_domain, "entra") == "alice@contoso.test"
        assert verified_email(base, "entra") == "alice@contoso.test"
        # Elsewhere, only what the provider verified.
        assert verified_email({**base, "email": "a@example.com"}, "oidc") is None
        verified = {**base, "email": "a@example.com", "email_verified": True}
        assert verified_email(verified, "oidc") == "a@example.com"


def test_discovery_is_read_outside_the_sign_in_transaction(at_okta, okta) -> None:
    """The login route reads the provider's document before it records the sign-in."""
    assert okta.discovery_reads == 0
    start = at_okta.get("/auth/login", follow_redirects=False)
    assert start.status_code == 302
    assert okta.discovery_reads == 1
    assert urlsplit(start.headers["location"]).path == "/oauth2/default/v1/authorize"


def test_the_cli_signs_in_through_a_discovered_provider(at_okta, okta) -> None:
    verifier, back = cli_sign_in(at_okta, okta, **groups("agentgov-auditor"))
    code = at_the_cli(back)["code"]
    out = at_okta.post("/auth/cli/token", json={"code": code, "verifier": verifier}).json()
    assert (out["name"], out["roles"]) == ("alice@example.com", ["auditor"])
