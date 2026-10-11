"""agentgateway configuration generation."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from agentgov.config import Settings
from agentgov.gateway import render, to_yaml, with_available_keys, write_if_changed
from agentgov.models import Agent, ModelProvider, ToolServer

IMAGE = "ghcr.io/agentgateway/agentgateway:v1.6.0"
# A throwaway RSA public key, so validation does not need a running Keycloak.
JWKS = json.dumps(
    {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test",
                "use": "sig",
                "alg": "RS256",
                "e": "AQAB",
                "n": (
                    "pCDv-vs44XRUq9nakqCyo6bwXO_06RKr24On7lHOzmi7mRABs1On9EvWKburzU6q"
                    "GxFVKCcO-MexUwwepA7hyuupZ1s4llJ59U-LCDjSz0cuk38nynN7KdsFwVX1qBVe"
                    "H3lqBSzfZb-Doe_qSmartAiXpybpzJry6v7TqGUecxAZSGzZneNjfS2lYrUMyIXU"
                    "7OkQdzLUcuhBzDltbkKo7pEBE-g67rVvC6dEal7oI2INeGocdaSOGscg8PECDZ50"
                    "8mv-VKjR9ymu2S_r0Ul56jgUZ7Of4zb1CkPIbxooVBniOlC2JXBlZsc-JJcoYlLv"
                    "JSqqzcNp_kPUyZiDs2Hpjw"
                ),
            }
        ]
    }
)

SETTINGS = Settings(
    keycloak_issuer="http://localhost:8180/realms/agentgov",
    keycloak_jwks_url="http://keycloak:8080/realms/agentgov/protocol/openid-connect/certs",
    gateway_otlp_endpoint="http://otel-collector:4317",
)


def servers() -> list[ToolServer]:
    return [
        ToolServer(name="crm", url="http://crm:9000/mcp", status="approved"),
        ToolServer(name="hr", url="https://hr.example.com/mcp", status="blocked"),
        ToolServer(name="new", url="http://new/mcp", status="pending"),
    ]


def providers(keys: str = "/model-keys") -> list[ModelProvider]:
    return [
        ModelProvider(name="openai", kind="openai", status="approved", key_file=f"{keys}/openai"),
        ModelProvider(
            name="groq",
            kind="openai-compatible",
            base_url="https://api.groq.com/openai/v1",
            status="approved",
            key_file=f"{keys}/groq",
        ),
        ModelProvider(
            name="vllm",
            kind="openai-compatible",
            base_url="http://vllm:8000",
            status="approved",
            key_file=f"{keys}/vllm",
        ),
        ModelProvider(name="claude", kind="anthropic", status="blocked", key_file=f"{keys}/claude"),
    ]


def routes(config: dict) -> dict[str, dict]:
    return {r["name"]: r for r in config["binds"][0]["listeners"][0]["routes"]}


def test_one_route_per_reviewed_server() -> None:
    config = render(servers(), SETTINGS)
    assert set(routes(config)) == {"mcp-crm", "mcp-hr", "agentgov-health"}  # pending excluded
    crm = routes(config)["mcp-crm"]
    assert crm["matches"] == [{"path": {"exact": "/mcp/crm"}}]
    assert crm["backends"] == [
        {"mcp": {"targets": [{"name": "crm", "mcp": {"host": "http://crm:9000/mcp"}}]}}
    ]


def test_every_route_is_authenticated_and_governed() -> None:
    policies = routes(render(servers(), SETTINGS))["mcp-crm"]["policies"]
    assert policies["jwtAuth"]["mode"] == "strict"
    assert policies["jwtAuth"]["audiences"] == ["agentgov-gateway"]
    processor = policies["mcpGuardrails"]["processors"][0]
    assert processor["kind"] == "remote"
    assert processor["failureMode"] == "failClosed"
    assert processor["methods"]["tools/call"] == "full"
    assert processor["methods"]["tools/list"] == "response"
    assert processor["metadata"]["client_id"] == "jwt.azp"
    assert processor["metadata"]["request"] == "mcpGuardrails"
    # The person the agent acts for, if any.
    assert processor["metadata"]["username"] == "jwt.preferred_username"
    assert processor["metadata"]["groups"] == "jwt.groups"
    assert processor["metadata"]["act"] == "jwt.act"
    assert "authorization" in processor["requestHeaders"]["disallowed"]


def test_monitor_mode_relaxes_authentication() -> None:
    config = render(servers(), SETTINGS, {"unknown-callers": "monitor"})
    assert routes(config)["mcp-crm"]["policies"]["jwtAuth"]["mode"] == "optional"


def test_mcp_gateway_off_publishes_no_tool_servers() -> None:
    config = render(servers(), SETTINGS, {"mcp-gateway": "off"})
    assert list(routes(config)) == ["agentgov-health"]


class TestModelRoutes:
    def test_one_route_per_provider(self) -> None:
        config = render([], SETTINGS, providers=providers())
        assert set(routes(config)) == {
            "llm-openai",
            "llm-groq",
            "llm-vllm",
            "llm-claude",
            "agentgov-health",
        }
        openai = routes(config)["llm-openai"]
        assert openai["matches"] == [{"path": {"exact": "/llm/openai/v1/chat/completions"}}]
        assert openai["backends"] == [{"ai": {"name": "openai", "provider": {"openAI": {}}}}]
        assert routes(config)["llm-claude"]["backends"][0]["ai"]["provider"] == {"anthropic": {}}

    def test_openai_compatible_servers(self) -> None:
        config = render([], SETTINGS, providers=providers())
        groq = routes(config)["llm-groq"]
        assert groq["backends"][0]["ai"]["hostOverride"] == "api.groq.com:443"
        assert groq["backends"][0]["ai"]["pathPrefix"] == "/openai/v1"
        assert groq["policies"]["backendTLS"] == {}
        vllm = routes(config)["llm-vllm"]
        assert vllm["backends"][0]["ai"]["hostOverride"] == "vllm:8000"
        assert "pathPrefix" not in vllm["backends"][0]["ai"]
        assert "backendTLS" not in vllm["policies"]

    def test_every_prompt_and_answer_goes_to_the_processor(self) -> None:
        policies = routes(render([], SETTINGS, providers=providers()))["llm-openai"]["policies"]
        assert policies["jwtAuth"]["mode"] == "strict"
        assert policies["backendAuth"] == {"key": {"file": "/model-keys/openai"}}
        assert policies["urlRewrite"] == {"path": {"full": "/v1/chat/completions"}}
        guard = policies["ai"]["promptGuard"]
        assert guard["streaming"] == "Enabled"
        for phase in ("request", "response"):
            webhook = guard[phase][0]["webhook"]
            assert webhook["target"] == {"host": "processor:8091"}
            assert webhook["failureMode"] == "failClosed"
            assert webhook["headers"]["x-agentgov-agent-id"] == "jwt.agent_id"
            assert webhook["headers"]["x-agentgov-provider"] == '"openai"'
            # The person, lists and objects as JSON.
            assert webhook["headers"]["x-agentgov-subject"] == "jwt.sub"
            assert webhook["headers"]["x-agentgov-groups"] == "toJson(jwt.groups)"
            assert webhook["headers"]["x-agentgov-act"] == "toJson(jwt.act)"

    def test_model_gateway_off_publishes_no_providers(self) -> None:
        config = render(servers(), SETTINGS, {"model-gateway": "off"}, providers())
        assert not [name for name in routes(config) if name.startswith("llm-")]
        assert "mcp-crm" in routes(config)

    def test_access_logs_carry_the_agent(self) -> None:
        log = render([], SETTINGS)["frontendPolicies"]["accessLog"]
        assert log["otlp"] == {"host": "otel-collector:4317", "protocol": "grpc"}
        assert log["add"] == {"agentgov.agent_id": "jwt.agent_id", "agentgov.client_id": "jwt.azp"}

    def test_a_missing_key_answers_503_instead_of_breaking_the_config(self) -> None:
        config = render(servers(), SETTINGS, providers=providers())
        checked = with_available_keys(config, exists=lambda path: path.endswith("/openai"))
        assert "backendAuth" in routes(checked)["llm-openai"]["policies"]
        groq = routes(checked)["llm-groq"]
        assert groq["policies"]["directResponse"]["status"] == 503
        assert "/model-keys/groq" in groq["policies"]["directResponse"]["body"]
        assert groq["matches"] == routes(config)["llm-groq"]["matches"]
        assert routes(checked)["mcp-crm"] == routes(config)["mcp-crm"]
        assert "backendAuth" in routes(config)["llm-groq"]["policies"]  # not modified in place


def test_tracing_and_ipv6() -> None:
    config = render([], SETTINGS)
    tracing = config["frontendPolicies"]["tracing"]
    assert (tracing["host"], tracing["protocol"]) == ("otel-collector:4317", "grpc")
    assert config["config"]["enableIpv6"] is False


def test_atomic_write(tmp_path: Path) -> None:
    target = tmp_path / "gw" / "config.yaml"
    content = to_yaml(render(servers(), SETTINGS))
    assert write_if_changed(str(target), content) is True
    assert write_if_changed(str(target), content) is False
    assert yaml.safe_load(target.read_text())["binds"]
    assert list(target.parent.iterdir()) == [target]  # no temp files left behind


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=False)
    return probe.returncode == 0


def a2a_agents() -> list[Agent]:
    """An agent other agents call over A2A: its route has external authorization for
    calls and external processing for answers."""
    return [
        Agent(
            id="agt_billing",
            name="billing-agent",
            status="active",
            a2a_url="http://billing-agent:9200/",
            source="registered",
        )
    ]


@pytest.mark.skipif(not _docker_ready(), reason=f"docker or {IMAGE} not available")
def test_agentgateway_accepts_generated_config(tmp_path: Path) -> None:
    config = render(servers(), SETTINGS, providers=providers("/cfg/keys"), agents=a2a_agents())
    routes = {r["name"]: r for r in config["binds"][0]["listeners"][0]["routes"]}
    assert "extProc" in routes["a2a-billing-agent"]["policies"]
    for route in config["binds"][0]["listeners"][0]["routes"]:
        if "jwtAuth" in route.get("policies", {}):
            route["policies"]["jwtAuth"]["jwks"] = JWKS
    (tmp_path / "config.yaml").write_text(to_yaml(config))
    (tmp_path / "keys").mkdir()
    for name in ("openai", "groq", "vllm", "claude"):
        (tmp_path / "keys" / name).write_text("sk-test")
        (tmp_path / "keys" / name).chmod(0o644)
    # agentgateway runs as a non-root user; pytest's tmp dirs are private.
    tmp_path.chmod(0o755)
    (tmp_path / "keys").chmod(0o755)
    (tmp_path / "config.yaml").chmod(0o644)
    proc = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{tmp_path}:/cfg:ro",
            IMAGE,
            "-f",
            "/cfg/config.yaml",
            "--validate-only",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert "Configuration is valid" in proc.stdout + proc.stderr, proc.stdout + proc.stderr


class TestServedConfig:
    """Gateways that don't share a volume with the control plane fetch their config."""

    def test_the_control_plane_serves_it_to_the_service_only(self, client) -> None:
        from tests.conftest import ADMIN, SERVICE, seed

        seed(client)
        auditor = client.post(
            "/v1/apikeys", json={"name": "audit", "role": "auditor"}, headers=ADMIN
        ).json()["token"]
        assert client.get("/v1/gateway/config").status_code == 401
        refused = client.get("/v1/gateway/config", headers={"Authorization": f"Bearer {auditor}"})
        assert refused.status_code == 403
        resp = client.get("/v1/gateway/config", headers=SERVICE)
        assert resp.status_code == 200 and resp.headers["content-type"] == "application/yaml"
        routes = yaml.safe_load(resp.text)["binds"][0]["listeners"][0]["routes"]
        assert [r["name"] for r in routes] == ["mcp-crm", "agentgov-health"]
        etag = resp.headers["ETag"]
        unchanged = client.get("/v1/gateway/config", headers={**SERVICE, "If-None-Match": etag})
        assert unchanged.status_code == 304

    def test_the_sidecar_keeps_a_copy_current(self, client, tmp_path: Path) -> None:
        from agentgov.gateway import Fetched, keep_current, sync_from_control_plane
        from tests.conftest import SERVICE, seed

        path = str(tmp_path / "gateway" / "config.yaml")
        client.headers.update(SERVICE)
        keep_current(client, path, interval=0, once=True)
        assert "mcp-crm" not in Path(path).read_text()

        fetched = Fetched()
        assert sync_from_control_plane(client, path, fetched) is False  # same content
        etag = fetched.etag
        assert sync_from_control_plane(client, path, fetched) is False  # 304
        assert fetched.etag == etag

        client.headers.pop("Authorization")
        seed(client)  # registers and approves the crm server
        client.headers.update(SERVICE)
        assert sync_from_control_plane(client, path, fetched) is True
        assert "mcp-crm" in Path(path).read_text()

    def test_the_sidecar_publishes_a_provider_once_its_key_is_there(
        self, client, tmp_path: Path
    ) -> None:
        from agentgov.gateway import Fetched, sync_from_control_plane
        from tests.conftest import ADMIN, SERVICE

        key = tmp_path / "keys" / "openai"
        client.post(
            "/v1/models/providers",
            json={"name": "openai", "kind": "openai", "key_file": str(key)},
            headers=ADMIN,
        ).raise_for_status()
        path, fetched = str(tmp_path / "gateway" / "config.yaml"), Fetched()
        client.headers.update(SERVICE)
        assert sync_from_control_plane(client, path, fetched) is True
        llm = routes(yaml.safe_load(Path(path).read_text()))["llm-openai"]
        assert llm["policies"]["directResponse"]["status"] == 503
        # The key appears; the configuration from the control plane doesn't change.
        key.parent.mkdir()
        key.write_text("sk-test")
        assert sync_from_control_plane(client, path, fetched) is True
        llm = routes(yaml.safe_load(Path(path).read_text()))["llm-openai"]
        assert llm["policies"]["backendAuth"] == {"key": {"file": str(key)}}

    def test_the_sidecar_retries_until_the_control_plane_answers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import httpx

        from agentgov import gateway

        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] < 3:
                raise httpx.ConnectError("control plane starting")
            return httpx.Response(200, text="binds: []\n", headers={"ETag": '"x"'})

        heartbeat = tmp_path / "alive"
        beats: list[float] = []
        # Every round touches the heartbeat, also while the control plane doesn't answer.
        monkeypatch.setattr(
            gateway.time, "sleep", lambda _: beats.append(heartbeat.stat().st_mtime)
        )
        client = httpx.Client(base_url="http://cp", transport=httpx.MockTransport(handler))
        path = tmp_path / "config.yaml"
        gateway.keep_current(client, str(path), interval=1, once=True, heartbeat=str(heartbeat))
        assert calls["n"] == 3 and yaml.safe_load(path.read_text()) == {"binds": []}
        assert len(beats) == 2 and heartbeat.exists()
