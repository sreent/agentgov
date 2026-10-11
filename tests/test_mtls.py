"""Mutual TLS between AgentGov's components (agentgov.tls)."""

from __future__ import annotations

import ssl
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from agentgov import tls
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.gateway import render, to_yaml
from tests.conftest import ADMIN, SERVICE, seed
from tests.test_gateway import IMAGE, JWKS, SETTINGS, _docker_ready, providers, servers


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    """An authority, and certificates for a server and a client from it."""
    authority = tls.make_authority(tmp_path / "ca")
    tls.issue(authority, tmp_path / "server", "agentgov-server", ["localhost", "127.0.0.1"])
    tls.issue(authority, tmp_path / "client", "agentgov-client", ["client"])
    return tmp_path


def test_the_certificates(certs: Path) -> None:
    server = certs / "server"
    assert (server / tls.KEY).stat().st_mode & 0o777 == 0o600
    assert (certs / "ca" / "ca.key").stat().st_mode & 0o777 == 0o600
    verified = subprocess.run(
        ["openssl", "verify", "-CAfile", str(certs / "ca" / "ca.crt"), str(server / tls.CERT)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert verified.returncode == 0, verified.stderr
    described = subprocess.run(
        ["openssl", "x509", "-in", str(server / tls.CERT), "-noout", "-ext",
         "subjectAltName,extendedKeyUsage"],
        capture_output=True, text=True, check=False,
    ).stdout  # fmt: skip
    assert "DNS:localhost" in described and "IP Address:127.0.0.1" in described
    assert "TLS Web Server Authentication" in described
    assert "TLS Web Client Authentication" in described
    # Made again, what is there is kept.
    before = (server / tls.KEY).read_bytes()
    tls.issue(certs / "ca", server, "agentgov-server", ["localhost"])
    assert (server / tls.KEY).read_bytes() == before
    with pytest.raises(ValueError, match="lacks"):
        tls.Identity.from_dir(certs / "ca")


@pytest.fixture
def served(certs: Path) -> Iterator[int]:
    """A server over mutual TLS, as the processor's webhook and the control plane's
    internal listener are; yields its port."""
    app = Starlette(routes=[Route("/", lambda request: PlainTextResponse("hello"))])
    identity = tls.Identity.from_dir(certs / "server")
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning",
                            **identity.uvicorn_options())  # fmt: skip
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield port
    server.should_exit = True
    thread.join(5)


def test_only_callers_with_a_certificate_from_the_authority(served: int, certs: Path) -> None:
    url = f"https://localhost:{served}/"
    client = tls.Identity.from_dir(certs / "client")
    assert httpx.get(url, verify=client.client_context()).text == "hello"
    # Without a certificate: refused in the handshake.
    bare = ssl.create_default_context(cafile=str(certs / "ca" / "ca.crt"))
    with pytest.raises(httpx.HTTPError):
        httpx.get(url, verify=bare)
    # With one from another authority.
    other = tls.make_authority(certs / "other-ca")
    tls.issue(other, certs / "intruder", "intruder", ["intruder"])
    intruder = ssl.create_default_context(cafile=str(certs / "ca" / "ca.crt"))
    intruder.load_cert_chain(str(certs / "intruder" / tls.CERT), str(certs / "intruder" / tls.KEY))
    with pytest.raises(httpx.HTTPError):
        httpx.get(url, verify=intruder)
    # And the client checks the server: one with a certificate from elsewhere is refused.
    elsewhere = ssl.create_default_context(cafile=str(certs / "other-ca" / "ca.crt"))
    elsewhere.load_cert_chain(str(certs / "client" / tls.CERT), str(certs / "client" / tls.KEY))
    with pytest.raises(httpx.HTTPError):
        httpx.get(url, verify=elsewhere)


@pytest.fixture
def mtls(settings: Settings, certs: Path) -> Settings:
    return settings.with_overrides(tls_dir=str(certs / "server"))


def test_the_service_role_only_on_the_internal_port(mtls: Settings) -> None:
    app = create_app(mtls, background=False)
    with TestClient(app) as public, TestClient(tls.InternalListener(app)) as internal:
        seed(public)
        # On the public port, the service token alone is refused: a component calls the
        # internal port, with its certificate.
        refused = public.get("/v1/gateway/config", headers=SERVICE)
        assert refused.status_code == 403 and "8443" in refused.json()["detail"]
        assert public.get("/v1/gateway/config").status_code == 401
        # On the internal port the certificate vouches for the component, with or without
        # the token (OPA sends no token).
        assert internal.get("/v1/gateway/config", headers=SERVICE).status_code == 200
        assert internal.get("/v1/gateway/config").status_code == 200
        # Administrators sign in as before, on either.
        assert public.get("/v1/agents", headers=ADMIN).status_code == 200
        assert internal.get("/v1/agents", headers=ADMIN).status_code == 200
        # A wrong token isn't a certificate's worth.
        bad = {"Authorization": "Bearer nope"}
        assert internal.get("/v1/agents", headers=bad).status_code == 401
        # Nor does an API key with the service role get it on the public port.
        made = public.post("/v1/apikeys", json={"name": "svc", "role": "service"}, headers=ADMIN)
        service_key = {"Authorization": f"Bearer {made.json()['token']}"}
        assert public.get("/v1/gateway/config", headers=service_key).status_code == 403
        assert internal.get("/v1/gateway/config", headers=service_key).status_code == 200


def test_without_certificates_nothing_changes(client: TestClient) -> None:
    assert client.get("/v1/gateway/config", headers=SERVICE).status_code == 200


def _processor_policies(config: dict) -> list[dict]:
    found = []
    for route in config["binds"][0]["listeners"][0]["routes"]:
        policies = route.get("policies", {})
        for processor in policies.get("mcpGuardrails", {}).get("processors", []):
            found.append(processor.get("policies"))
        guard = policies.get("ai", {}).get("promptGuard", {})
        for step in [*guard.get("request", []), *guard.get("response", [])]:
            found.append(step["webhook"]["target"].get("policies"))
        if "extAuthz" in policies:
            found.append(policies["extAuthz"].get("policies"))
    return found


def test_the_gateway_calls_the_processor_with_its_certificate(certs: Path) -> None:
    plain = render(servers(), SETTINGS, providers=providers())
    assert all(p is None for p in _processor_policies(plain))
    settings = SETTINGS.with_overrides(tls_dir=str(certs / "server"))
    config = render(servers(), settings, providers=providers())
    found = _processor_policies(config)
    assert found and all(p and p["backendTLS"]["cert"] == "/tls/tls.crt" for p in found)
    grpc = config["binds"][0]["listeners"][0]["routes"][0]["policies"]["mcpGuardrails"]
    assert grpc["processors"][0]["policies"]["backendTLS"] == {
        "cert": "/tls/tls.crt",
        "key": "/tls/tls.key",
        "root": "/tls/ca.crt",
        "hostname": settings.processor_address.rsplit(":", 1)[0],
        "alpn": ["h2"],
    }


@pytest.mark.skipif(not _docker_ready(), reason=f"docker or {IMAGE} not available")
def test_agentgateway_accepts_it(certs: Path, tmp_path: Path) -> None:
    settings = SETTINGS.with_overrides(tls_dir=str(certs / "server"), gateway_tls_dir="/tls")
    config = render(servers(), settings, providers=providers("/cfg/keys"))
    for route in config["binds"][0]["listeners"][0]["routes"]:
        if "jwtAuth" in route.get("policies", {}):
            route["policies"]["jwtAuth"]["jwks"] = JWKS
    folder = tmp_path / "cfg"
    (folder / "keys").mkdir(parents=True)
    for name in ("openai", "groq", "vllm", "claude"):
        (folder / "keys" / name).write_text("sk-test")
    (folder / "config.yaml").write_text(to_yaml(config))
    gateway = certs / "client"
    for path in [folder, folder / "keys", gateway, *folder.rglob("*"), *gateway.iterdir()]:
        path.chmod(0o755 if path.is_dir() else 0o644)  # agentgateway runs as a non-root user
    tmp_path.chmod(0o755)
    certs.chmod(0o755)
    proc = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{folder}:/cfg:ro", "-v", f"{gateway}:/tls:ro",
         IMAGE, "-f", "/cfg/config.yaml", "--validate-only"],
        capture_output=True, text=True, check=False, timeout=120,
    )  # fmt: skip
    assert "Configuration is valid" in proc.stdout + proc.stderr, proc.stdout + proc.stderr
