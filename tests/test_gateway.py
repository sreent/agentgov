"""agentgateway configuration generation."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from agentgov.config import Settings
from agentgov.gateway import render, to_yaml, write_if_changed
from agentgov.models import ToolServer

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
    assert "authorization" in processor["requestHeaders"]["disallowed"]


def test_monitor_mode_relaxes_authentication() -> None:
    policies = routes(render(servers(), SETTINGS.with_overrides(unknown_agent_mode="monitor")))[
        "mcp-crm"
    ]["policies"]
    assert policies["jwtAuth"]["mode"] == "optional"


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


@pytest.mark.skipif(not _docker_ready(), reason=f"docker or {IMAGE} not available")
def test_agentgateway_accepts_generated_config(tmp_path: Path) -> None:
    config = render(servers(), SETTINGS)
    for route in config["binds"][0]["listeners"][0]["routes"]:
        if "jwtAuth" in route.get("policies", {}):
            route["policies"]["jwtAuth"]["jwks"] = JWKS
    (tmp_path / "config.yaml").write_text(to_yaml(config))
    # agentgateway runs as a non-root user; pytest's tmp dirs are private.
    tmp_path.chmod(0o755)
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
