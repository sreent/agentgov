"""Identity issuers the gateway trusts: their tokens taken there, as Keycloak's are, without
Keycloak (docs/agent-identity.md#straight-to-the-gateway). The issuers themselves, and
Keycloak's side, are in tests/test_identity_issuers.py."""

from __future__ import annotations

import asyncio
import json
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from sqlalchemy import select
from starlette.testclient import TestClient

from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.gateway import render, to_yaml
from agentgov.identity import issuer_keys
from agentgov.models import DISCOVERED, Agent, IdentityIssuer, ModelUsage
from agentgov.opa import bundle
from agentgov.processor.a2a_answers import _identity as answer_identity
from agentgov.processor.control_plane import DecisionRecorder
from agentgov.processor.server import GovernanceProcessor
from agentgov.registry import discovery, features, identity_issuers, manifests, model_usage
from agentgov.registry.errors import ValidationError
from tests.conftest import ADMIN, SERVICE
from tests.test_cli import _Shared, ok, runner
from tests.test_gateway import (
    IMAGE,
    JWKS,
    SETTINGS,
    _docker_ready,
    a2a_agents,
    providers,
    routes,
    servers,
)
from tests.test_identity_issuers import CLUSTER, ENTRA, SA, SPIRE, _register
from tests.test_model_guard import allow, check, prompt, user
from tests.test_models import access_log, logs
from tests.test_processor import FakeControlPlane, FakeOpa, call_request, run

KEY = json.loads(JWKS)["keys"][0]
# The second key an issuer may publish: the same public numbers, another key ID.
NEXT = {**KEY, "kid": "next"}
DISCOVERY = "/.well-known/openid-configuration"
CLUSTER_URL = CLUSTER["issuer"]
ENTRA_URL = ENTRA["issuer"]
KEYCLOAK = SETTINGS.keycloak_issuer


def issuer_server(keys: dict[str, list[dict[str, Any]]]) -> httpx.MockTransport:
    """Issuers' discovery documents and key sets: ``keys`` by issuer URL; any other URL
    answers 404."""

    def handle(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        for issuer, found in keys.items():
            if url == issuer + DISCOVERY:
                return httpx.Response(200, json={"issuer": issuer, "jwks_uri": issuer + "/jwks"})
            if url == issuer + "/jwks":
                return httpx.Response(200, json={"keys": found})
        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handle)


def trusted(name: str, issuer: str, *, audience: str | None = None) -> IdentityIssuer:
    """An issuer the gateway takes tokens from, as the gateway's configuration is given it."""
    return IdentityIssuer(
        name=name,
        kind="oidc",
        issuer=issuer,
        audience=audience,
        gateway=True,
        gateway_keys=[KEY],
        status="approved",
    )


def gateway_issuer(s: Any, spec: dict[str, Any], keys: list[dict[str, Any]] | None) -> Any:
    """An issuer trusted at the gateway, with ``keys`` as if AgentGov had fetched them."""
    issuer = identity_issuers.create(s, {**spec, "gateway": True}, actor="admin:a")
    if keys is not None:
        issuer_keys.store(s, {issuer.id: keys})
    return identity_issuers.get(s, issuer.id)


@pytest.fixture
def app_client(settings: Settings) -> Iterator[TestClient]:
    """The API, with issuers' keys served by issuer_server."""
    app = create_app(settings, background=False)
    with TestClient(app) as client:
        app.state.rt.issuer_http = httpx.Client(
            transport=issuer_server({CLUSTER_URL: [KEY], ENTRA_URL: [KEY, NEXT]})
        )
        yield client


class TestKeys:
    def test_only_public_signing_keys_with_a_key_id_are_kept(self) -> None:
        found = {
            "keys": [
                NEXT,
                {k: v for k, v in KEY.items() if k != "kid"},  # agentgateway won't load it
                {**KEY, "kid": "enc", "use": "enc"},
                {"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"},
                {**KEY, "kid": "a-private-one", "d": "secret", "p": "x", "q": "y"},
                "not a key",
            ]
        }
        kept = issuer_keys.vet(found, "https://idp/jwks")
        assert [k["kid"] for k in kept] == ["a-private-one", "next"]
        assert not {"d", "p", "q"} & set(kept[0])

    def test_nothing_usable_is_an_error(self) -> None:
        for found, error in (
            ([], "not a key set"),
            ({"issuer": "https://idp"}, "not a key set"),
            ({"keys": [{"kty": "RSA", "n": "x", "e": "AQAB"}]}, "no signing keys with a key ID"),
        ):
            with pytest.raises(issuer_keys.IssuerKeysError, match=error):
                issuer_keys.vet(found, "https://idp/jwks")

    def test_keys_are_found_from_the_discovery_document_or_a_key_set(self) -> None:
        http = httpx.Client(transport=issuer_server({CLUSTER_URL: [KEY]}))
        assert issuer_keys.fetch(CLUSTER_URL + DISCOVERY, http) == [KEY]
        assert issuer_keys.fetch(CLUSTER_URL + "/jwks", http) == [KEY]
        with pytest.raises(issuer_keys.IssuerKeysError, match="couldn't read"):
            issuer_keys.fetch("https://elsewhere" + DISCOVERY, http)

    def test_where_they_are(self) -> None:
        cluster = IdentityIssuer(issuer=CLUSTER_URL + "/", keys_url=None)
        assert issuer_keys.keys_location(cluster) == CLUSTER_URL + DISCOVERY
        cluster.keys_url = "https://k8s.example.com/openid/v1/jwks"
        assert issuer_keys.keys_location(cluster) == cluster.keys_url

    def test_the_last_good_keys_stay_when_a_fetch_fails(self, rt) -> None:
        with rt.db.session() as s:
            issuer = gateway_issuer(s, CLUSTER, None)
            issuer_id = issuer.id
            assert issuer_keys.targets(s) == [(issuer_id, CLUSTER_URL + DISCOVERY)]
            assert issuer_keys.store(s, {issuer_id: [KEY]}) == {
                "changed": ["cluster"],
                "failed": [],
            }
            assert issuer_keys.store(s, {issuer_id: [KEY]})["changed"] == []
            down = issuer_keys.IssuerKeysError("couldn't read it")
            assert issuer_keys.store(s, {issuer_id: down}) == {
                "changed": ["cluster"],
                "failed": ["cluster"],
            }
            issuer.refresh_from_db()
            assert issuer.gateway_keys == [KEY]
            assert issuer.keys_error == "couldn't read it"
            # The same failure again changes nothing the gateway is given.
            assert issuer_keys.store(s, {issuer_id: down})["changed"] == []
            issuer_keys.store(s, {issuer_id: [KEY, NEXT]})
            issuer.refresh_from_db()
            assert (issuer.gateway_keys, issuer.keys_error) == ([KEY, NEXT], None)

    def test_only_issuers_the_gateway_trusts_are_fetched_and_kept(self, rt) -> None:
        with rt.db.session() as s:
            cluster = identity_issuers.create(s, CLUSTER, actor="admin:a")
            assert issuer_keys.targets(s) == []
            assert issuer_keys.store(s, {cluster.id: [KEY]})["changed"] == []
            assert cluster.gateway_keys is None

    def test_the_runtime_fetches_them_outside_a_transaction(self, rt) -> None:
        rt.issuer_http = httpx.Client(transport=issuer_server({CLUSTER_URL: [KEY]}))
        with rt.db.session() as s:
            gateway_issuer(s, CLUSTER, None)
            gateway_issuer(s, ENTRA, None)
        assert rt.refresh_issuer_keys() == {"changed": ["cluster", "entra"], "failed": ["entra"]}
        with rt.db.session() as s:
            assert identity_issuers.get(s, "cluster").gateway_keys == [KEY]
            assert "404" in identity_issuers.get(s, "entra").keys_error


class TestIssuers:
    def test_the_gateway_takes_oidc_and_kubernetes_tokens(self, rt) -> None:
        with rt.db.session() as s:
            with pytest.raises(ValidationError, match="gateway is true"):
                identity_issuers.create(s, {**CLUSTER, "gateway": "yes"}, actor="a")
            with pytest.raises(ValidationError, match="SPIFFE trust domain's JWT-SVIDs"):
                identity_issuers.create(s, {**SPIRE, "gateway": True}, actor="a")
            assert gateway_issuer(s, CLUSTER, [KEY]).gateway
            assert gateway_issuer(s, ENTRA, [KEY]).gateway

    def test_no_longer_trusted_there_its_keys_go(self, rt) -> None:
        with rt.db.session() as s:
            issuer = gateway_issuer(s, CLUSTER, [KEY])
            issuer_keys.store(s, {issuer.id: issuer_keys.IssuerKeysError("down")})
            assert identity_issuers.update(s, issuer, {"gateway": False}, actor="a") == ["gateway"]
            issuer.refresh_from_db()  # as stored
            assert (issuer.gateway_keys, issuer.keys_at, issuer.keys_error) == (None, None, None)
            assert identity_issuers.gateway_state(issuer) == {
                "trusted": False,
                "taking": False,
                "keys": 0,
                "keys_at": None,
                "error": None,
            }

    def test_whose_tokens_the_gateway_takes(self, rt, settings) -> None:
        with rt.db.session() as s:
            cluster = gateway_issuer(s, CLUSTER, [KEY])
            gateway_issuer(s, ENTRA, None)  # no keys yet
            identity_issuers.create(s, SPIRE, actor="a")  # through Keycloak
            assert [i.name for i in identity_issuers.at_the_gateway(s)] == ["cluster"]
            assert identity_issuers.gateway_state(cluster)["taking"]
            identity_issuers.set_status(s, cluster, "block", actor="a")
            assert identity_issuers.at_the_gateway(s) == []
            assert not identity_issuers.gateway_state(cluster)["taking"]
            identity_issuers.set_status(s, cluster, "unblock", actor="a")
            # Agents' own identities off: no issuer is trusted, in Keycloak or here.
            features.set_mode(s, settings, "workload-identity", "off", actor="a")
            assert identity_issuers.at_the_gateway(s) == []
            assert identity_issuers.gateway_state(cluster)["taking"]  # as far as it goes
            assert not identity_issuers.gateway_state(cluster, on=False)["taking"]

    def test_manifests_say_whether_the_gateway_takes_its_tokens(self, rt, settings) -> None:
        doc = {
            "apiVersion": manifests.API_VERSION,
            "kind": "IdentityIssuer",
            "metadata": {"name": "cluster"},
            "spec": {"kind": "kubernetes", "issuer": CLUSTER_URL, "gateway": True},
        }
        with rt.db.session() as s:
            assert manifests.apply(s, settings, [doc], actor="ci")[0]["action"] == "created"
            assert identity_issuers.get(s, "cluster").gateway
        with rt.db.session() as s:
            exported = {d["kind"]: d for d in manifests.export(s)}
            assert exported["IdentityIssuer"]["spec"] == {**doc["spec"], "status": "approved"}
            assert manifests.apply(s, settings, [doc], actor="ci")[0]["action"] == "unchanged"


class TestApi:
    def test_its_keys_are_fetched_as_it_is_trusted(self, app_client) -> None:
        created = app_client.post(
            "/v1/identity-issuers", json={**CLUSTER, "gateway": True}, headers=ADMIN
        )
        assert created.status_code == 201, created.text
        state = created.json()["gateway"]
        assert (state["trusted"], state["taking"], state["keys"], state["error"]) == (
            True,
            True,
            1,
            None,
        )
        listed = app_client.get("/v1/identity-issuers", headers=ADMIN).json()
        assert listed[0]["gateway"]["taking"]
        # Not trusted there: nothing fetched.
        plain = app_client.post("/v1/identity-issuers", json=ENTRA, headers=ADMIN).json()
        assert plain["gateway"] == {
            "trusted": False,
            "taking": False,
            "keys": 0,
            "keys_at": None,
            "error": None,
        }
        changed = app_client.patch(
            "/v1/identity-issuers/entra", json={"gateway": True}, headers=ADMIN
        ).json()
        assert changed["gateway"]["keys"] == 2

    def test_keys_it_cant_fetch_are_said_at_once(self, app_client) -> None:
        elsewhere = {**ENTRA, "issuer": "https://login.example.com/v2.0", "gateway": True}
        created = app_client.post("/v1/identity-issuers", json=elsewhere, headers=ADMIN)
        assert created.status_code == 201
        state = created.json()["gateway"]
        assert not state["taking"]
        assert "couldn't read https://login.example.com/v2.0/.well-known" in state["error"]
        health = {
            f["key"]: f for f in app_client.get("/v1/features", headers=ADMIN).json()["features"]
        }["workload-identity"]
        assert health["status"] == "limited"
        assert "The gateway can't take entra's tokens: couldn't read" in health["problems"][0]

    def test_fetched_again_on_demand(self, app_client) -> None:
        app_client.post("/v1/identity-issuers", json={**CLUSTER, "gateway": True}, headers=ADMIN)
        app_client.post("/v1/identity-issuers", json=ENTRA, headers=ADMIN)
        rt = app_client.app.state.rt
        rt.issuer_http = httpx.Client(transport=issuer_server({CLUSTER_URL: [KEY, NEXT]}))
        fetched = app_client.post("/v1/identity-issuers/cluster/keys", headers=ADMIN)
        assert fetched.status_code == 200
        assert fetched.json()["gateway"]["keys"] == 2
        refused = app_client.post("/v1/identity-issuers/entra/keys", headers=ADMIN)
        assert refused.status_code == 409
        assert "doesn't take entra's tokens" in refused.json()["detail"]

    def test_keycloak_is_agentgovs_own(self, database_url) -> None:
        settings = Settings(
            database_url=database_url,
            admin_token="test-admin",
            keycloak_issuer=KEYCLOAK,
            keycloak_jwks_url=SETTINGS.keycloak_jwks_url,
        )
        with TestClient(create_app(settings, background=False)) as client:
            own = {"name": "keycloak", "kind": "oidc", "issuer": KEYCLOAK + "/", "gateway": True}
            refused = client.post("/v1/identity-issuers", json=own, headers=ADMIN)
            assert refused.status_code == 409
            assert "AgentGov's own Keycloak" in refused.json()["detail"]
            assert client.get("/v1/identity-issuers", headers=ADMIN).json() == []

    def test_how_an_agent_calls_the_gateway_with_its_own_token(self, app_client) -> None:
        app_client.post("/v1/identity-issuers", json={**CLUSTER, "gateway": True}, headers=ADMIN)
        app_client.post("/v1/identity-issuers", json=ENTRA, headers=ADMIN)
        for name, issuer, subject in (("bot", "cluster", SA), ("other", "entra", "f0e1")):
            app_client.post(
                "/v1/agents",
                json={
                    "name": name,
                    "sponsors": ["a"],
                    "approve": True,
                    "workload_identity": {"issuer": issuer, "subject": subject},
                },
                headers=ADMIN,
            ).raise_for_status()
        creds = app_client.post("/v1/agents/bot/credentials", json={}, headers=ADMIN)
        assert creds.status_code == 200, creds.text
        assert creds.json() == {
            "method": "workload-identity",
            "issuer": "cluster",
            "subject": SA,
            # Its token for the gateway's address: not one every install's gateway takes.
            "gateway": {
                "url": "http://localhost:8080",
                "issuer": CLUSTER_URL,
                "audience": "http://localhost:8080",
            },
        }
        # Neither Keycloak nor the gateway takes the other's tokens.
        other = app_client.post("/v1/agents/other/credentials", json={}, headers=ADMIN)
        assert other.status_code == 409


class TestGatewayConfig:
    ISSUERS = [trusted("cluster", CLUSTER_URL), trusted("entra", ENTRA_URL, audience="api://ag")]

    def test_without_trusted_issuers_nothing_changes(self) -> None:
        config = render(servers(), SETTINGS, providers=providers())
        crm = routes(config)["mcp-crm"]["policies"]
        assert crm["jwtAuth"]["issuer"] == KEYCLOAK
        assert "providers" not in crm["jwtAuth"]
        metadata = crm["mcpGuardrails"]["processors"][0]["metadata"]
        assert metadata["agent_id"] == "jwt.agent_id"
        assert "issuer" not in metadata
        log = config["frontendPolicies"]["accessLog"]["add"]
        assert log == {"agentgov.agent_id": "jwt.agent_id", "agentgov.client_id": "jwt.azp"}

    def test_each_trusted_issuers_tokens_are_checked_with_its_keys(self) -> None:
        config = render(servers(), SETTINGS, providers=providers(), issuers=self.ISSUERS)
        for name in ("mcp-crm", "llm-openai"):
            auth = routes(config)[name]["policies"]["jwtAuth"]
            assert [p["issuer"] for p in auth["providers"]] == [KEYCLOAK, CLUSTER_URL, ENTRA_URL]
            keycloak, cluster, entra = auth["providers"]
            assert keycloak["jwks"] == {"url": SETTINGS.keycloak_jwks_url}
            # The keys AgentGov fetched, written in: the gateway never fetches them.
            assert json.loads(cluster["jwks"]) == {"keys": [KEY]}
            # Their tokens are for this gateway (its address), or the audience the issuer
            # names; Keycloak's, AgentGov's own, carry the gateway's audience.
            assert keycloak["audiences"] == [SETTINGS.gateway_audience]
            assert cluster["audiences"] == [SETTINGS.gateway_public_url]
            assert entra["audiences"] == ["api://ag"]

    def test_only_agentgovs_own_tokens_name_the_agent_and_the_person(self) -> None:
        config = render(
            servers(),
            SETTINGS,
            {"data-protection": "enforce"},
            providers=providers(),
            agents=a2a_agents(),
            issuers=self.ISSUERS,
        )
        own = f'has(jwt.iss) && jwt.iss == "{KEYCLOAK}"'
        crm = routes(config)["mcp-crm"]["policies"]
        metadata = crm["mcpGuardrails"]["processors"][0]["metadata"]
        assert metadata["agent_id"] == f"{own} ? jwt.agent_id : null"
        assert metadata["username"] == f"{own} ? jwt.preferred_username : null"
        assert (metadata["issuer"], metadata["subject"]) == ("jwt.iss", "jwt.sub")
        guard = TestGatewayConfig._guard_headers(routes(config)["llm-openai"]["policies"])
        assert guard["x-agentgov-agent-id"] == f"{own} ? jwt.agent_id : null"
        assert guard["x-agentgov-email"] == f"{own} ? jwt.email : null"
        assert guard["x-agentgov-issuer"] == "jwt.iss"
        assert guard["x-agentgov-subject"] == "jwt.sub"
        answers = routes(config)["a2a-billing-agent"]["policies"]["extProc"]["metadataContext"]
        claims = answers["agentgov"]
        assert claims["agent_id"].startswith(f"{own} ? (") and claims["agent_id"].endswith(': ""')
        assert claims["issuer"] == 'has(jwt.iss) ? jwt.iss : ""'
        log = config["frontendPolicies"]["accessLog"]["add"]
        assert log["agentgov.agent_id"] == f"{own} ? jwt.agent_id : null"
        assert (log["agentgov.issuer"], log["agentgov.subject"]) == ("jwt.iss", "jwt.sub")

    @staticmethod
    def _guard_headers(policies: dict[str, Any]) -> dict[str, str]:
        """The headers the gateway sets on its calls to the processor's model webhook."""
        found: dict[str, str] = {}

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                for k, v in value.items():
                    if isinstance(k, str) and k.startswith("x-agentgov-") and isinstance(v, str):
                        found[k] = v
                    walk(v)
            elif isinstance(value, list):
                for v in value:
                    walk(v)

        walk(policies)
        return found

    def test_without_keycloak_only_issuers_tokens_are_taken(self) -> None:
        config = render(servers(), Settings(), providers=providers(), issuers=self.ISSUERS)
        crm = routes(config)["mcp-crm"]["policies"]
        assert [p["issuer"] for p in crm["jwtAuth"]["providers"]] == [CLUSTER_URL, ENTRA_URL]
        metadata = crm["mcpGuardrails"]["processors"][0]["metadata"]
        assert not {"agent_id", "client_id", "username", "email", "act"} & set(metadata)
        assert metadata["issuer"] == "jwt.iss"
        # Models are reachable: the gateway can check the callers' tokens.
        model = routes(config)["llm-openai"]
        assert model["policies"]["jwtAuth"]["mode"] == "strict"
        assert "directResponse" not in model["policies"]
        alone = render(servers(), Settings(), providers=providers())
        assert "directResponse" in routes(alone)["llm-openai"]["policies"]

    def test_developers_sign_in_to_keycloak_for_tool_servers(self) -> None:
        config = render(
            servers(),
            SETTINGS,
            {"developer-sign-in": "on"},
            providers=providers(),
            issuers=self.ISSUERS,
        )
        crm = routes(config)["mcp-crm"]["policies"]
        assert crm["mcpAuthentication"]["issuer"] == KEYCLOAK
        assert "providers" not in crm["mcpAuthentication"]
        assert "jwtAuth" not in crm
        # Models take every trusted issuer's tokens still.
        model = routes(config)["llm-openai"]["policies"]["jwtAuth"]
        assert len(model["providers"]) == 3

    def test_the_control_plane_renders_the_issuers_it_takes(self, app_client) -> None:
        app_client.post("/v1/identity-issuers", json={**CLUSTER, "gateway": True}, headers=ADMIN)
        app_client.post("/v1/identity-issuers", json=ENTRA, headers=ADMIN)
        crm_server = {"name": "crm", "url": "http://crm/mcp"}
        app_client.post("/v1/toolservers", json=crm_server, headers=ADMIN)
        served = yaml.safe_load(app_client.get("/v1/gateway/config", headers=SERVICE).text)
        crm = routes(served)["mcp-crm"]["policies"]["jwtAuth"]
        assert [p["issuer"] for p in crm["providers"]] == [CLUSTER_URL]
        app_client.post("/v1/identity-issuers/cluster/block", headers=ADMIN)
        served = yaml.safe_load(app_client.get("/v1/gateway/config", headers=SERVICE).text)
        assert "jwtAuth" not in routes(served)["mcp-crm"]["policies"]

    @pytest.mark.skipif(not _docker_ready(), reason=f"docker or {IMAGE} not available")
    def test_agentgateway_accepts_it(self, tmp_path: Path) -> None:
        config = render(
            servers(),
            SETTINGS,
            {"a2a-masking": "enforce"},
            providers=providers("/cfg/keys"),
            agents=a2a_agents(),
            issuers=self.ISSUERS,
        )
        for route in config["binds"][0]["listeners"][0]["routes"]:
            for provider in (route.get("policies", {}).get("jwtAuth") or {}).get("providers", []):
                if provider["issuer"] == KEYCLOAK:
                    provider["jwks"] = JWKS  # no running Keycloak to fetch them from
        (tmp_path / "config.yaml").write_text(to_yaml(config))
        (tmp_path / "keys").mkdir()
        for name in ("openai", "groq", "vllm", "claude"):
            (tmp_path / "keys" / name).write_text("sk-test")
            (tmp_path / "keys" / name).chmod(0o644)
        tmp_path.chmod(0o755)
        (tmp_path / "keys").chmod(0o755)
        (tmp_path / "config.yaml").chmod(0o644)
        proc = subprocess.run(
            [
                *("docker", "run", "--rm", "-v", f"{tmp_path}:/cfg:ro", IMAGE),
                *("-f", "/cfg/config.yaml", "--validate-only"),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        assert "Configuration is valid" in proc.stdout + proc.stderr, proc.stdout + proc.stderr


class TestPolicyData:
    def test_workloads_name_agents_by_issuer_and_subject(self, rt, settings) -> None:
        with rt.db.session() as s:
            gateway_issuer(s, CLUSTER, [KEY])
            identity_issuers.create(s, ENTRA, actor="a")  # its agents come through Keycloak
            bot = _register(s, settings, "bot", {"issuer": "cluster", "subject": SA})
            pending = _register(
                s, settings, "new", {"issuer": "cluster", "subject": "sa:new"}, approve=False
            )
            _register(s, settings, "entra-bot", {"issuer": "entra", "subject": "f0e1"})
            seen = discovery.observe(
                s, source="gateway", name="sa:seen", issuer=CLUSTER_URL, subject="sa:seen"
            )
            assert seen is not None and seen.status == DISCOVERED
            snapshot = bundle.registry_snapshot(s)
            # The agent a token names, pending ones too (refused as such); not one found but
            # not adopted yet.
            assert snapshot["workloads"] == {CLUSTER_URL: {SA: bot.id, "sa:new": pending.id}}

    def test_none_while_the_issuer_is_blocked_or_own_identities_are_off(self, rt, settings) -> None:
        with rt.db.session() as s:
            cluster = gateway_issuer(s, CLUSTER, [KEY])
            _register(s, settings, "bot", {"issuer": "cluster", "subject": SA})
            identity_issuers.set_status(s, cluster, "block", actor="a")
            assert bundle.registry_snapshot(s)["workloads"] == {}
            identity_issuers.set_status(s, cluster, "unblock", actor="a")
            assert bundle.registry_snapshot(s)["workloads"] != {}
            features.set_mode(s, settings, "workload-identity", "off", actor="a")
            assert bundle.registry_snapshot(s)["workloads"] == {}


class WorkloadOpa(FakeOpa):
    """OPA, whose data names agt_1 by its workload identity at CLUSTER_URL."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.lookups: list[dict[str, Any]] = []

    async def evaluate(self, path: str, input_doc: dict[str, Any]):
        if path == "agentgov/context/workload_agent":
            self.lookups.append(input_doc["agent"])
            agent = input_doc["agent"]
            known = (agent.get("issuer"), agent.get("subject")) == (CLUSTER_URL, SA)
            return ("agt_1" if known else None), None
        return await super().evaluate(path, input_doc)


def workload_call(subject: str = SA) -> Any:
    """A tool call with a token of CLUSTER_URL: no agent or client AgentGov names."""
    return call_request(
        "get", {"id": "c-1"}, client_id="", agent_id="", issuer=CLUSTER_URL, subject=subject
    )


class TestProcessor:
    def test_a_workload_identity_names_the_agent(self) -> None:
        opa = WorkloadOpa()
        reply, cp = run(opa, request=workload_call())
        assert reply.WhichOneof("result") == "pass"
        assert opa.lookups == [{"issuer": CLUSTER_URL, "subject": SA}]
        decided = [inp for path, inp in opa.inputs if path.endswith("decision")]
        assert decided[0]["agent"] == {"issuer": CLUSTER_URL, "subject": SA, "agent_id": "agt_1"}
        assert cp.records[0]["identity"]["agent_id"] == "agt_1"

    def test_agentgovs_own_tokens_need_no_lookup(self) -> None:
        opa = WorkloadOpa()
        run(opa, request=call_request("get", {"id": "c-1"}, issuer=KEYCLOAK, subject="svc"))
        assert opa.lookups == []

    def test_another_subject_is_an_unknown_caller(self) -> None:
        opa = WorkloadOpa(
            lambda inp: {"effect": "allow", "reasons": [], "redact": [], "agent": None},
            modes={"unknown-callers": "monitor"},
        )
        _, cp = run(opa, request=workload_call("sa:stranger"))
        decided = [inp for path, inp in opa.inputs if path.endswith("decision")]
        assert decided[0]["agent"] == {"issuer": CLUSTER_URL, "subject": "sa:stranger"}
        observed = [payload for kind, payload in cp.calls if kind == "observe"]
        assert observed[0]["issuer"] == CLUSTER_URL
        assert observed[0]["subject"] == "sa:stranger"

    def test_opa_out_of_reach_leaves_the_caller_as_the_token_names_it(self) -> None:
        processor = GovernanceProcessor(
            Settings(),
            opa=FakeOpa(fail=True),
            control_plane=FakeControlPlane(),
            recorder=DecisionRecorder(FakeControlPlane()),
        )
        identity = {"issuer": CLUSTER_URL, "subject": SA}
        assert asyncio.run(processor.caller(identity)) == identity

    def test_model_calls_name_the_agent_by_its_workload_identity(self) -> None:
        opa = WorkloadOpa(allow())
        headers = {
            "x-agentgov-issuer": CLUSTER_URL,
            "x-agentgov-subject": SA,
            "x-agentgov-provider": "openai",
            "x-agentgov-model": "gpt-4o-mini",
        }
        _, cp = check(opa, prompt(user("hello")), headers=headers)
        decided = [inp for path, inp in opa.inputs if "decision" in path]
        assert decided[0]["agent"] == {"issuer": CLUSTER_URL, "subject": SA, "agent_id": "agt_1"}
        assert cp.records[0]["identity"]["agent_id"] == "agt_1"
        # A subject alone (AgentGov's own tokens') names a person, not a workload.
        assert "subject" not in TestProcessor._model_identity({"x-agentgov-subject": "u-1"})

    def test_providers_keys_are_spent_for_agents_alone(self) -> None:
        """While unknown callers are monitored, a model call from a subject of a trusted
        issuer that names no agent is refused all the same: anyone the issuer gives a token
        to could otherwise spend the provider's key. AgentGov's own tokens pass, recorded."""

        def unknown(inp: dict[str, Any]) -> dict[str, Any]:
            return {"effect": "deny", "reasons": ["Caller is not a registered agent"]}

        stranger = {
            "x-agentgov-issuer": CLUSTER_URL,
            "x-agentgov-subject": "sa:stranger",
            "x-agentgov-provider": "openai",
        }
        opa = WorkloadOpa(unknown, modes={"unknown-callers": "monitor"})
        result, cp = check(opa, prompt(user("hello")), headers=stranger)
        assert result != {"action": {}} and "not a registered agent" in json.dumps(result)
        assert [r["effect"] for r in cp.records] == ["deny"]
        # Still found, for someone to adopt.
        assert [p["subject"] for kind, p in cp.calls if kind == "observe"] == ["sa:stranger"]
        own = {
            "x-agentgov-issuer": KEYCLOAK,
            "x-agentgov-client-id": "svc",
            "x-agentgov-provider": "openai",
        }
        opa = WorkloadOpa(unknown, modes={"unknown-callers": "monitor"})
        result, cp = check(opa, prompt(user("hello")), headers=own)
        assert result == {"action": {}} and [r["effect"] for r in cp.records] == ["allow"]

    @staticmethod
    def _model_identity(headers: dict[str, str]) -> dict[str, Any]:
        from agentgov.processor.model_guard import ModelGuard

        return ModelGuard._identity(headers)

    def test_answers_between_agents_name_the_caller_alike(self) -> None:
        assert answer_identity({"agent_id": "", "issuer": CLUSTER_URL, "subject": SA}) == {
            "issuer": CLUSTER_URL,
            "subject": SA,
        }
        assert answer_identity({"agent_id": "agt_1", "subject": "u-1"}) == {"agent_id": "agt_1"}


class TestDiscoveryAndUsage:
    def test_a_workload_found_calling_takes_its_identity_with_it(self, rt, settings) -> None:
        with rt.db.session() as s:
            gateway_issuer(s, CLUSTER, [KEY])
            found = discovery.observe(
                s, source="gateway", name="sa:seen", issuer=CLUSTER_URL, subject="sa:seen"
            )
            assert found is not None
            assert (found.workload_issuer, found.workload_subject) == ("cluster", "sa:seen")
            again = discovery.observe(
                s, source="gateway", name="sa:seen", issuer=CLUSTER_URL, subject="sa:seen"
            )
            assert again is found
            # A token of an issuer the gateway doesn't trust names no workload.
            other = discovery.observe(
                s, source="gateway", name="elsewhere", issuer=ENTRA_URL, subject="x"
            )
            assert other is not None and other.workload_issuer is None

    def test_adopting_it_is_all_it_needs(self, app_client) -> None:
        app_client.post("/v1/identity-issuers", json={**CLUSTER, "gateway": True}, headers=ADMIN)
        observed = app_client.post(
            "/v1/internal/observe",
            json={"source": "gateway", "name": SA, "issuer": CLUSTER_URL, "subject": SA},
            headers=SERVICE,
        )
        assert observed.status_code == 200, observed.text
        rt = app_client.app.state.rt
        with rt.db.session() as s:
            agent = s.scalars(select(Agent).where(Agent.workload_subject == SA)).one()
            assert agent.status == DISCOVERED
            assert agent.workload_issuer == "cluster"

    def test_model_calls_are_metered_by_workload_identity(self, rt, settings) -> None:
        with rt.db.session() as s:
            gateway_issuer(s, CLUSTER, [KEY])
            bot = _register(s, settings, "bot", {"issuer": "cluster", "subject": SA})
            bot_id = bot.id

        def by(issuer: str, subject: str) -> dict[str, Any]:
            record = access_log()
            record["attributes"] += [
                {"key": "agentgov.issuer", "value": {"stringValue": issuer}},
                {"key": "agentgov.subject", "value": {"stringValue": subject}},
            ]
            return record

        with rt.db.session() as s:
            stats = model_usage.ingest_logs(
                s, logs(by(CLUSTER_URL, SA), by(CLUSTER_URL, "sa:other"), by(ENTRA_URL, SA))
            )
            assert (stats["model_calls"], stats["unidentified"]) == (3, 2)
            used = s.scalars(select(ModelUsage).where(ModelUsage.agent_id == bot_id)).all()
            assert sum(u.input_tokens for u in used) == 100


class TestCli:
    @pytest.fixture
    def agentgov(self, app_client, monkeypatch) -> Any:
        """``agentgov <args>`` as the bootstrap admin, against app_client's API."""
        from agentgov import cli

        def run(*args: str) -> Any:
            monkeypatch.setattr(cli, "_client", lambda: _Shared(app_client, "test-admin"))
            return runner.invoke(cli.app, list(args))

        return run

    def test_trusting_an_issuer_at_the_gateway(self, app_client, agentgov) -> None:
        out = ok(
            agentgov(
                "issuers",
                "create",
                "cluster",
                "--kind",
                "kubernetes",
                "--issuer",
                CLUSTER_URL,
                "--gateway",
            )
        )
        assert "the gateway: takes its tokens (1 key)" in out
        assert "takes its tokens (1 key)" in ok(agentgov("issuers", "list"))
        app_client.app.state.rt.issuer_http = httpx.Client(
            transport=issuer_server({CLUSTER_URL: [KEY, NEXT]})
        )
        out = ok(agentgov("issuers", "fetch-keys", "cluster"))
        assert "keys fetched" in out and "(2 keys)" in out
        ok(agentgov("issuers", "block", "cluster"))
        assert "not while the issuer is blocked" in ok(agentgov("issuers", "list"))
        out = ok(agentgov("issuers", "update", "cluster", "--no-gateway"))
        assert "the gateway:" not in out


class TestHealth:
    def test_developer_sign_in_keeps_tool_servers_on_keycloak(self, database_url) -> None:
        settings = Settings(
            database_url=database_url,
            admin_token="test-admin",
            keycloak_issuer=KEYCLOAK,
            keycloak_jwks_url=SETTINGS.keycloak_jwks_url,
        )
        app = create_app(settings, background=False)
        with TestClient(app) as client:
            app.state.rt.issuer_http = httpx.Client(transport=issuer_server({CLUSTER_URL: [KEY]}))
            client.post("/v1/identity-issuers", json={**CLUSTER, "gateway": True}, headers=ADMIN)
            on = {"mode": "on"}
            client.put("/v1/features/developer-sign-in", json=on, headers=ADMIN).raise_for_status()
            listed = client.get("/v1/features", headers=ADMIN).json()["features"]
        health = {f["key"]: f for f in listed}["workload-identity"]
        assert health["status"] == "limited"
        assert "tool servers there take only Keycloak's tokens" in health["problems"][0]
        assert "(cluster)" in health["problems"][0]

    def test_older_keys_kept_are_said(self, app_client) -> None:
        app_client.post("/v1/identity-issuers", json={**CLUSTER, "gateway": True}, headers=ADMIN)
        rt = app_client.app.state.rt
        rt.issuer_http = httpx.Client(transport=issuer_server({}))
        app_client.post("/v1/identity-issuers/cluster/keys", headers=ADMIN)
        listed = app_client.get("/v1/features", headers=ADMIN).json()["features"]
        problems = {f["key"]: f for f in listed}["workload-identity"]["problems"]
        assert problems[0].startswith("AgentGov can't fetch cluster's keys again (couldn't read")
        assert "the keys fetched before" in problems[0]
