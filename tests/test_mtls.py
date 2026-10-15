"""Mutual TLS between AgentGov's components (agentgov.tls)."""

from __future__ import annotations

import asyncio
import ssl
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest
import uvicorn
import yaml
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agentgov import tls
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.gateway import render, to_yaml
from tests.conftest import ADMIN, SERVICE, seed
from tests.test_gateway import IMAGE, JWKS, SETTINGS, _docker_ready, a2a_agents, providers, servers


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
        if "extProc" in policies:
            found.append(policies["extProc"].get("policies"))
    return found


def test_the_gateway_calls_the_processor_with_its_certificate(certs: Path) -> None:
    plain = render(servers(), SETTINGS, providers=providers(), agents=a2a_agents())
    assert all(p is None for p in _processor_policies(plain))
    settings = SETTINGS.with_overrides(tls_dir=str(certs / "server"))
    config = render(servers(), settings, providers=providers(), agents=a2a_agents())
    found = _processor_policies(config)
    assert len(found) >= 4  # tool calls, model calls, calls between agents, their answers
    assert all(p and p["backendTLS"]["cert"] == "/tls/tls.crt" for p in found)
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
    config = render(servers(), settings, providers=providers("/cfg/keys"), agents=a2a_agents())
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


# ------------------------------------------------- renewed certificates, and peers


def _serial(port: int, client: tls.Identity) -> int:
    """The serial number of the certificate the server on ``port`` shows."""
    import socket

    context = client.client_context()
    with (
        socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
        context.wrap_socket(raw, server_hostname="localhost") as conn,
    ):
        der = conn.getpeercert(binary_form=True)
    from cryptography import x509

    return x509.load_der_x509_certificate(der).serial_number


def _served(identity: tls.Identity) -> tuple[uvicorn.Server, threading.Thread, int]:
    async def who(request):  # type: ignore[no-untyped-def]
        # The client certificate the server saw (asyncio's transport has it).
        peer = request.scope.get("extensions", {}).get("tls", {})
        return PlainTextResponse(str(bool(peer)) if peer else "hello")

    app = Starlette(routes=[Route("/", who)])
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning",
                            **identity.uvicorn_options())  # fmt: skip
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    return server, thread, server.servers[0].sockets[0].getsockname()[1]


def test_a_renewed_certificate_serves_the_next_connections(certs: Path) -> None:
    server_identity = tls.Identity.from_dir(certs / "server")
    client = tls.Identity.from_dir(certs / "client")
    server, thread, port = _served(server_identity)
    try:
        first = _serial(port, client)
        # Nothing changed: nothing to take.
        assert server_identity.rotation.check() is False
        tls.issue(certs / "ca", certs / "server", "agentgov-server", ["localhost"], renew=True)
        assert server_identity.rotation.check() is True
        second = _serial(port, client)
        assert second != first
        # And the server still takes the client, whose certificate is renewed too: the
        # client presents its new one from its next connection.
        tls.issue(certs / "ca", certs / "client", "agentgov-client", ["client"], renew=True)
        assert client.rotation.check() is True
        url = f"https://localhost:{port}/"
        assert httpx.get(url, verify=client.client_context()).status_code == 200
    finally:
        server.should_exit = True
        thread.join(5)


def test_files_half_written_wait_for_the_rest(certs: Path) -> None:
    identity = tls.Identity.from_dir(certs / "server")
    rotation = identity.rotation
    tls.issue(certs / "ca", certs / "elsewhere", "agentgov-server", ["localhost"])
    # The certificate is there, its key not yet (spiffe-helper writes one after the other).
    (certs / "server" / tls.CERT).write_bytes((certs / "elsewhere" / tls.CERT).read_bytes())
    assert rotation.check() is False and rotation.version == 0
    (certs / "server" / tls.KEY).write_bytes((certs / "elsewhere" / tls.KEY).read_bytes())
    assert rotation.check() is True and rotation.version == 1


def test_the_watcher_looks_by_itself(certs: Path) -> None:
    identity = tls.Identity.from_dir(certs / "server", reload_seconds=0.2)
    rotation = identity.rotation
    tls.issue(certs / "ca", certs / "server", "agentgov-server", ["localhost"], renew=True)
    deadline = time.monotonic() + 5
    while rotation.version == 0 and time.monotonic() < deadline:
        time.sleep(0.05)
    rotation.stop()
    assert rotation.version == 1


def _svid(certs: Path, name: str, spiffe_id: str) -> Path:
    """A certificate as SPIRE issues one: its SPIFFE ID as a URI, no DNS name."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID

    ca_cert = x509.load_pem_x509_certificate((certs / "ca" / "ca.crt").read_bytes())
    ca_key = serialization.load_pem_private_key((certs / "ca" / "ca.key").read_bytes(), None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]), critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    folder = certs / name
    folder.mkdir()
    (folder / tls.CERT).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / tls.KEY).write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (folder / tls.CA).write_bytes((certs / "ca" / "ca.crt").read_bytes())
    return folder


GATEWAY_ID = "spiffe://example.org/ns/agentgov/sa/agentgov-gateway"


def test_peers_are_named_by_spiffe_id_or_dns_name() -> None:
    peers = tls.Peers.parse(f"{GATEWAY_ID}, opa, spiffe://example.org/ns/agentgov/sa/agentgov-*")
    assert peers.takes([GATEWAY_ID]) and peers.takes(["opa"])
    assert peers.takes(["spiffe://example.org/ns/agentgov/sa/agentgov-processor"])
    assert not peers.takes(["spiffe://example.org/ns/agents/sa/billing-agent", "billing"])
    assert tls.Peers().takes(["anyone"])  # none listed: any certificate from the authority


def test_only_the_peers_are_taken(certs: Path) -> None:
    gateway = tls.Identity.from_dir(_svid(certs, "gateway", GATEWAY_ID))
    agent = tls.Identity.from_dir(
        _svid(certs, "agent", "spiffe://example.org/ns/agents/sa/billing-agent")
    )
    by_name = tls.Identity.from_dir(certs / "client")  # DNS name: client
    server_identity = tls.Identity.from_dir(
        certs / "server", peers=tls.Peers.parse(f"{GATEWAY_ID},client")
    )
    server, thread, port = _served(server_identity)
    url = f"https://localhost:{port}/"
    try:
        assert httpx.get(url, verify=gateway.client_context()).status_code == 200
        assert httpx.get(url, verify=by_name.client_context()).status_code == 200
        # A workload with a certificate from the same authority, but not one of them.
        with pytest.raises(httpx.HTTPError):
            httpx.get(url, verify=agent.client_context())
    finally:
        server.should_exit = True
        thread.join(5)


def test_grpc_takes_renewed_certificates_and_only_its_peers(certs: Path) -> None:

    import grpc

    gateway = tls.Identity.from_dir(_svid(certs, "gateway", GATEWAY_ID))
    agent = tls.Identity.from_dir(
        _svid(certs, "agent", "spiffe://example.org/ns/agents/sa/billing-agent")
    )
    server_identity = tls.Identity.from_dir(certs / "server", peers=tls.Peers.parse(GATEWAY_ID))

    async def echo(request: bytes, context: object) -> bytes:
        return request

    def channel(client: tls.Identity, port: int) -> grpc.aio.Channel:
        creds = grpc.ssl_channel_credentials(
            root_certificates=Path(client.ca).read_bytes(),
            private_key=Path(client.key).read_bytes(),
            certificate_chain=Path(client.cert).read_bytes(),
        )
        return grpc.aio.secure_channel(
            f"localhost:{port}", creds, options=[("grpc.ssl_target_name_override", "localhost")]
        )

    async def scenario() -> None:
        server = grpc.aio.server(interceptors=server_identity.grpc_interceptors())
        handler = grpc.method_handlers_generic_handler(
            "test.Echo", {"Echo": grpc.unary_unary_rpc_method_handler(echo)}
        )
        server.add_generic_rpc_handlers((handler,))
        port = server.add_secure_port("127.0.0.1:0", server_identity.grpc_credentials())
        await server.start()
        try:
            async with channel(gateway, port) as ch:
                assert await ch.unary_unary("/test.Echo/Echo")(b"hi") == b"hi"
            async with channel(agent, port) as ch:
                with pytest.raises(grpc.aio.AioRpcError) as refused:
                    await ch.unary_unary("/test.Echo/Echo")(b"hi")
                assert refused.value.code() == grpc.StatusCode.PERMISSION_DENIED
            # Renewed: new handshakes get the new certificate, and calls go on.
            tls.issue(certs / "ca", certs / "server", "agentgov-server", ["localhost"], renew=True)
            assert server_identity.rotation.check() is True
            async with channel(gateway, port) as ch:
                assert await ch.unary_unary("/test.Echo/Echo")(b"again") == b"again"
        finally:
            await server.stop(None)

    asyncio.run(scenario())


# ------------------------------------- clients that live on, and agentgateway's files


@contextmanager
def _who_calls(identity: tls.Identity) -> Iterator[int]:
    """An HTTPS server that answers with the serial number of its caller's certificate,
    and keeps connections open (HTTP/1.1)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from cryptography import x509

    class Echo(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            der = self.request.getpeercert(binary_form=True)
            body = str(x509.load_der_x509_certificate(der).serial_number).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    httpd.daemon_threads = True
    httpd.socket = identity.server_context().wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_clients_that_live_on_present_the_renewed_certificate(
    certs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = tls.Identity.from_dir(certs / "server")
    client = tls.Identity.from_dir(certs / "client")
    made = client.client_context()

    def renew() -> None:
        tls.issue(certs / "ca", certs / "client", "agentgov-client", ["client"], renew=True)
        assert client.rotation.check() is True

    with (
        _who_calls(server) as port,
        httpx.Client(base_url=f"https://localhost:{port}", transport=client.transport()) as http,
    ):
        first = http.get("/").text
        renew()
        # The next request goes through a new pool, which presents the new certificate.
        second = http.get("/").text
        assert second != first
        # The pool it replaced is kept a while (what it carried finishes), then closed.
        pools = http._transport._pools  # type: ignore[attr-defined]
        assert len(pools._retired) == 1
        monkeypatch.setattr(tls._Pools, "GRACE_SECONDS", 0.0)
        renew()
        third = http.get("/").text
        # With no while to wait, the one replaced now closed at once (the first waits on).
        assert third not in (first, second) and len(pools._retired) == 1
        # A context, once made, is never changed: a client made from it before still
        # presents what it did; one made now, the newest.
        assert httpx.get(f"https://localhost:{port}/", verify=made).text == first
        assert client.client_context() is not made
        newest = client.client_context()
        assert httpx.get(f"https://localhost:{port}/", verify=newest).text == third

        async def asynchronous() -> tuple[str, str]:
            async with httpx.AsyncClient(
                base_url=f"https://localhost:{port}", transport=client.async_transport()
            ) as http:
                before = (await http.get("/")).text
                renew()
                return before, (await http.get("/")).text

        before, after = asyncio.run(asynchronous())
        assert before == third and after != third


def test_a_renewed_gateway_certificate_rewrites_its_configuration(certs: Path) -> None:
    """agentgateway reads the files it calls the processor with only as it loads its
    configuration: the gateway's renewed certificate rewrites that, once taken, so that it
    loads them again."""
    from agentgov.gateway import Fetched, sync_from_control_plane

    control_plane = httpx.Client(
        base_url="http://control-plane",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, text="binds: []\n", headers={"ETag": '"x"'})
        ),
    )
    gateway = tls.Identity.from_dir(certs / "client")
    path, fetched = certs / "config.yaml", Fetched()

    def sync() -> bool:
        return sync_from_control_plane(control_plane, str(path), fetched, certificates=gateway)

    assert sync() is True and sync() is False
    tls.issue(certs / "ca", certs / "elsewhere", "agentgov-client", ["client"])
    # The key is there, its certificate not yet: not taken, nothing rewritten.
    (certs / "client" / tls.KEY).write_bytes((certs / "elsewhere" / tls.KEY).read_bytes())
    assert gateway.rotation.check() is False and sync() is False
    (certs / "client" / tls.CERT).write_bytes((certs / "elsewhere" / tls.CERT).read_bytes())
    assert gateway.rotation.check() is True and sync() is True
    # Only a comment changed: the configuration is the control plane's.
    assert yaml.safe_load(path.read_text()) == {"binds": []}
    assert gateway.fingerprint()[:16] in path.read_text()


def test_internal_certs_renews_from_the_same_authority(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from agentgov import cli

    runner = CliRunner()

    def internal_certs(*args: str) -> None:
        result = runner.invoke(cli.app, ["internal-certs", str(tmp_path), *args])
        assert result.exit_code == 0, result.output

    internal_certs("--component", "processor=processor,processor.agentgov")
    processor = tmp_path / "processor"
    key, authority = (processor / tls.KEY).read_bytes(), (tmp_path / "ca" / tls.CA).read_bytes()
    internal_certs("--component", "processor")  # what is there is kept
    assert (processor / tls.KEY).read_bytes() == key
    internal_certs("--component", "processor=processor,processor.agentgov", "--renew")
    assert (processor / tls.KEY).read_bytes() != key
    assert (processor / tls.CA).read_bytes() == authority == (tmp_path / "ca" / tls.CA).read_bytes()
    assert (processor / tls.KEY).stat().st_mode & 0o777 == 0o600
    verified = subprocess.run(
        ["openssl", "verify", "-CAfile", str(processor / tls.CA), str(processor / tls.CERT)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert verified.returncode == 0, verified.stderr
