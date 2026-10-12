"""Mutual TLS between AgentGov's components.

Each component (the control plane, the governance processor, OPA, agentgateway and the
OpenTelemetry Collector) holds a certificate from AgentGov's own certificate authority,
in a directory as cert-manager writes a certificate's Secret: ``tls.crt``, ``tls.key`` and
the authority's ``ca.crt`` (AGENTGOV_TLS_DIR). With them, a component serves TLS on its
internal ports and asks whoever calls for a certificate from the same authority, and it
presents its own when it calls another component. Nothing else on the network can pose
as the processor that decides on tool calls, or as OPA, or reach them.

``agentgov internal-certs DIR`` makes an authority and a certificate for each component,
where cert-manager isn't there to (Compose, or a cluster without it). The certificates can
come from SPIFFE / SPIRE instead (X.509-SVIDs, written to the same files by spiffe-helper),
or cert-manager: whoever renews them, each component reads its files again when they change
(AGENTGOV_TLS_RELOAD_SECONDS) and serves, and presents, the new certificate from the next
connection on, with no restart (``Rotation``).

Where the authority issues certificates to more than AgentGov's components, such as a SPIRE
server that gives every pod one, a certificate from it doesn't make its holder a component:
AGENTGOV_TLS_PEERS names the callers a component's listeners take, by their SPIFFE IDs or
DNS names (``Peers``).
"""

from __future__ import annotations

import datetime
import hashlib
import inspect
import ipaddress
import logging
import ssl
import tempfile
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger(__name__)

CERT, KEY, CA = "tls.crt", "tls.key", "ca.crt"
CERTIFICATE_DAYS = 3650
# Marks a request that came in on the control plane's internal listener (asgi scope
# state), where every caller showed a certificate from AgentGov's authority.
INTERNAL = "agentgov.internal"


class PeerRefused(ssl.SSLError):
    """A caller whose certificate the authority signed, but which isn't one this listener
    takes."""


@dataclass(frozen=True)
class Peers:
    """The callers a listener takes, by the names in their certificates: SPIFFE IDs (URI
    SANs) or DNS names, each exact or, ending with ``*``, a prefix. None listed: any
    certificate from the authority."""

    allowed: tuple[str, ...] = ()

    @classmethod
    def parse(cls, text: str | None) -> Peers:
        return cls(tuple(p.strip() for p in (text or "").split(",") if p.strip()))

    def takes(self, names: Iterable[str]) -> bool:
        if not self.allowed:
            return True
        return any(
            name == want or (want.endswith("*") and name.startswith(want[:-1]))
            for want in self.allowed
            for name in names
        )

    @staticmethod
    def names_in(peer: dict[str, Any] | None) -> list[str]:
        """The URI and DNS names in a certificate as ``getpeercert()`` gives it."""
        return [v for kind, v in (peer or {}).get("subjectAltName", ()) if kind in ("URI", "DNS")]

    @staticmethod
    def names_in_pem(pem: bytes) -> list[str]:
        cert = x509.load_pem_x509_certificate(pem)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            return []
        return [
            *san.get_values_for_type(x509.UniformResourceIdentifier),
            *san.get_values_for_type(x509.DNSName),
        ]


@dataclass(frozen=True)
class Files:
    """A certificate, its key and the authority's certificate, as read together: what a
    component serves and presents comes from one reading of its files."""

    cert: bytes
    key: bytes
    ca: bytes

    def fingerprint(self) -> str:
        digest = hashlib.sha256()
        for part in (self.cert, self.key, self.ca):
            digest.update(part)
            digest.update(b"\0")
        return digest.hexdigest()


@dataclass(frozen=True)
class Identity:
    """A component's certificate, its key, and the authority it trusts; the callers its
    listeners take; and how often it looks for a renewed certificate (0: never)."""

    cert: str
    key: str
    ca: str
    peers: Peers = field(default_factory=Peers)
    reload_seconds: float = 0.0

    @classmethod
    def from_dir(
        cls, directory: str | Path, *, peers: Peers | None = None, reload_seconds: float = 0.0
    ) -> Identity:
        folder = Path(directory)
        found = cls(
            str(folder / CERT),
            str(folder / KEY),
            str(folder / CA),
            peers=peers or Peers(),
            reload_seconds=reload_seconds,
        )
        missing = [p for p in (found.cert, found.key, found.ca) if not Path(p).is_file()]
        if missing:
            raise ValueError(f"AGENTGOV_TLS_DIR lacks {', '.join(missing)}")
        return found

    def read(self) -> Files:
        return Files(*(Path(p).read_bytes() for p in (self.cert, self.key, self.ca)))

    def fingerprint(self) -> str:
        """The certificate this component holds: its files as it last took them."""
        return self.rotation.fingerprint()

    @cached_property
    def rotation(self) -> Rotation:
        return Rotation(self)

    def server_context(self) -> ssl.SSLContext:
        """For a server that asks every caller for a certificate from the authority (and,
        with peers, one of theirs), and serves the newest certificate."""
        return self.rotation.server_context()

    def client_context(self) -> ssl.SSLContext:
        """For calling another component, from a client made for the call: it checks the
        other's certificate, and presents this one, the newest. Public services (an
        https:// URL elsewhere) are checked against the system's roots too. A client that
        lives on takes ``transport()`` instead."""
        return self.rotation.client_context()

    def transport(self) -> httpx.BaseTransport:
        """For a long-lived httpx.Client calling other components: its new connections
        present the newest certificate."""
        return RenewingTransport(self.rotation)

    def async_transport(self) -> httpx.AsyncBaseTransport:
        """``transport()``, for an httpx.AsyncClient."""
        return AsyncRenewingTransport(self.rotation)

    def grpc_credentials(self) -> Any:
        return self.rotation.grpc_credentials()

    def grpc_interceptors(self) -> list[Any]:
        """What checks a gRPC caller is one of the peers (none without peers)."""
        return [peer_interceptor(self.peers)] if self.peers.allowed else []

    def uvicorn_options(self) -> dict[str, Any]:
        return {"ssl_context_factory": lambda config, default: self.server_context()}


def _load(context: ssl.SSLContext, files: Files) -> ssl.SSLContext:
    """``context`` with the certificate, key and authority in ``files``. ssl reads a
    certificate and its key only from files: it reads private copies, so that it takes what
    was read, whatever the writer of the originals does meanwhile."""
    with tempfile.TemporaryDirectory(prefix="agentgov-tls-") as folder:
        cert, key = Path(folder, CERT), Path(folder, KEY)
        cert.write_bytes(files.cert)
        key.write_bytes(files.key)
        context.load_cert_chain(cert, key)
    context.load_verify_locations(cadata=files.ca.decode())
    return context


def _server(files: Files) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    return _load(context, files)


class Rotation:
    """Keeps a component's certificate current. Every ``reload_seconds`` it reads its
    files; when they changed, and the certificate and key fit together (spiffe-helper, for
    one, writes one file after the other), the new certificate serves the next
    connections: servers switch to it as each handshake starts, clients made from then on
    present it, and gRPC takes it at the next handshake. Connections open already keep
    theirs. A context is never changed once made (OpenSSL's aren't safe to change while
    others use them): each certificate gets new ones."""

    def __init__(self, identity: Identity) -> None:
        self.identity = identity
        self._lock = threading.Lock()
        self._files = identity.read()
        self._server = _server(self._files)
        self._client: ssl.SSLContext | None = None
        self._client_version = 0
        self.version = 0
        self._stopped = threading.Event()
        if identity.reload_seconds > 0:
            threading.Thread(target=self._watch, name="tls-rotation", daemon=True).start()

    def _watch(self) -> None:
        while not self._stopped.wait(self.identity.reload_seconds):
            try:
                self.check()
            except Exception:  # keep watching whatever went wrong this time
                log.exception("couldn't check the TLS files for a renewed certificate")

    def stop(self) -> None:
        """Stop looking for renewals."""
        self._stopped.set()

    def check(self) -> bool:
        """Take renewed files, if they changed and fit together; whether it did."""
        try:
            files = self.identity.read()
        except OSError as exc:
            log.info("couldn't read the TLS files (%s): later", exc)
            return False
        if files == self._files:
            return False
        try:
            server = _server(files)
        except (ssl.SSLError, OSError, ValueError) as exc:
            log.info("the TLS files changed but don't fit together yet (%s): later", exc)
            return False
        with self._lock:
            self._files, self._server = files, server
            self.version += 1
        log.info("renewed TLS certificate taken from %s", self.identity.cert)
        return True

    def fingerprint(self) -> str:
        with self._lock:
            return self._files.fingerprint()

    def current(self) -> ssl.SSLContext:
        with self._lock:
            return self._server

    def server_context(self) -> ssl.SSLContext:
        with self._lock:
            files = self._files
        context = _server(files)

        def newest(connection: Any, server_name: str | None, original: ssl.SSLContext) -> None:
            # Each handshake starts with the newest certificate (and the authority it trusts),
            # whether or not the caller named the server (SNI).
            connection.context = self.current()

        context.sni_callback = newest
        peers = self.identity.peers
        if peers.allowed:
            context.sslobject_class = _checked_object(peers)
        return context

    def client(self) -> tuple[ssl.SSLContext, int]:
        """A client context with the newest certificate, and the version it has."""
        with self._lock:
            if self._client is None or self._client_version != self.version:
                self._client = _load(ssl.create_default_context(), self._files)
                self._client_version = self.version
            return self._client, self._client_version

    def client_context(self) -> ssl.SSLContext:
        return self.client()[0]

    def grpc_credentials(self) -> Any:
        import grpc

        def configuration(files: Files) -> Any:
            return grpc.ssl_server_certificate_configuration(
                [(files.key, files.cert)], root_certificates=files.ca
            )

        with self._lock:
            given, files = [self.version], self._files

        def fetch() -> Any:
            # Called before each handshake: a new configuration once the files changed.
            with self._lock:
                version, latest = self.version, self._files
            if version == given[0]:
                return None
            given[0] = version
            return configuration(latest)

        return grpc.dynamic_ssl_server_credentials(
            configuration(files), fetch, require_client_authentication=True
        )


class _Pools:
    """httpx transports for a long-lived client, one per certificate: requests go through
    the newest; one a renewal replaced closes once what it carried is long done."""

    GRACE_SECONDS = 300.0

    def __init__(self, rotation: Rotation, make: Callable[[ssl.SSLContext], Any]) -> None:
        self._rotation, self._make = rotation, make
        self._lock = threading.Lock()
        context, self._version = rotation.client()
        self._current = make(context)
        self._retired: list[tuple[float, Any]] = []

    def next(self) -> tuple[Any, list[Any]]:
        """The transport for the next request, and the replaced ones due to close."""
        now = time.monotonic()
        with self._lock:
            if self._version != self._rotation.version:
                context, self._version = self._rotation.client()
                self._retired.append((now + self.GRACE_SECONDS, self._current))
                self._current = self._make(context)
            due = [transport for at, transport in self._retired if at <= now]
            self._retired = [(at, transport) for at, transport in self._retired if at > now]
            return self._current, due

    def every(self) -> list[Any]:
        with self._lock:
            transports = [self._current, *(transport for _, transport in self._retired)]
            self._retired = []
            return transports


class RenewingTransport(httpx.BaseTransport):
    """``Identity.transport()``."""

    def __init__(self, rotation: Rotation) -> None:
        self._pools = _Pools(rotation, lambda context: httpx.HTTPTransport(verify=context))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        transport, due = self._pools.next()
        for old in due:
            old.close()
        return transport.handle_request(request)  # type: ignore[no-any-return]

    def close(self) -> None:
        for transport in self._pools.every():
            transport.close()


class AsyncRenewingTransport(httpx.AsyncBaseTransport):
    """``Identity.async_transport()``."""

    def __init__(self, rotation: Rotation) -> None:
        self._pools = _Pools(rotation, lambda context: httpx.AsyncHTTPTransport(verify=context))

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        transport, due = self._pools.next()
        for old in due:
            await old.aclose()
        return await transport.handle_async_request(request)  # type: ignore[no-any-return]

    async def aclose(self) -> None:
        for transport in self._pools.every():
            await transport.aclose()


def _checked_object(peers: Peers) -> type[ssl.SSLObject]:
    """SSLObjects (asyncio's TLS, so uvicorn's) that end a handshake with a caller that
    isn't one of ``peers``."""

    class Checked(ssl.SSLObject):
        def do_handshake(self) -> None:
            super().do_handshake()
            names = Peers.names_in(self.getpeercert())
            if not peers.takes(names):
                log.warning("refused a TLS caller that isn't one of the peers: %s", names)
                raise PeerRefused(f"{', '.join(names) or 'a caller'} isn't one of the peers")

    return Checked


def peer_interceptor(peers: Peers) -> Any:
    """For gRPC servers: what refuses each call from a caller that isn't one of ``peers``."""
    import grpc

    class PeerInterceptor(grpc.aio.ServerInterceptor):  # type: ignore[misc]
        async def intercept_service(self, continuation: Callable[..., Any], details: Any) -> Any:
            return _guarded(await continuation(details), peers)

    return PeerInterceptor()


def _guarded(handler: Any, peers: Peers) -> Any:
    """``handler``'s method, which first checks the caller is one of ``peers``."""
    import grpc

    if handler is None:
        return None

    async def check(context: Any) -> None:
        pem = (context.auth_context().get("x509_pem_cert") or [b""])[0]
        names = Peers.names_in_pem(pem) if pem else []
        if not peers.takes(names):
            log.warning("refused a gRPC caller that isn't one of the peers: %s", names)
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "not one of the peers")

    def guarded(behaviour: Any, streams_out: bool) -> Any:
        if streams_out and inspect.isasyncgenfunction(behaviour):

            async def stream(request: Any, context: Any) -> Any:
                await check(context)
                async for reply in behaviour(request, context):
                    yield reply

            return stream

        async def call(request: Any, context: Any) -> Any:
            await check(context)
            return await behaviour(request, context)

        return call

    kinds = (
        ("unary_unary", grpc.unary_unary_rpc_method_handler, False),
        ("unary_stream", grpc.unary_stream_rpc_method_handler, True),
        ("stream_unary", grpc.stream_unary_rpc_method_handler, False),
        ("stream_stream", grpc.stream_stream_rpc_method_handler, True),
    )
    for attr, make, streams_out in kinds:
        behaviour = getattr(handler, attr)
        if behaviour is not None:
            return make(
                guarded(behaviour, streams_out),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
    return handler


class InternalListener:
    """ASGI middleware for the control plane's internal listener: marks each request as
    having come from a component (the listener took only callers with a certificate)."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] in ("http", "websocket"):
            scope.setdefault("state", {})[INTERNAL] = True
        await self.app(scope, receive, send)


# --------------------------------------------------------------------- making them


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _write(path: Path, data: bytes, mode: int) -> None:
    """Replace ``path`` at once (a component reading it sees the old file or the new)."""
    temporary = path.with_name(f".{path.name}.new")
    temporary.write_bytes(data)
    temporary.chmod(mode)
    temporary.replace(path)


def _names(hosts: Iterable[str]) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = []
    for host in hosts:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    return names


def make_authority(directory: str | Path, *, name: str = "AgentGov internal CA") -> Path:
    """An authority in ``directory`` (``ca.crt``, ``ca.key``); one there already is kept."""
    folder = Path(directory)
    cert_path, key_path = folder / CA, folder / "ca.key"
    if cert_path.exists() and key_path.exists():
        return folder
    folder.mkdir(parents=True, exist_ok=True)
    key = _key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CERTIFICATE_DAYS))
        # No limit on the path below it: SPIRE, with it as its upstream authority, signs
        # with an intermediate of its own.
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        # Key identifiers: strict verifiers (Python 3.13's default) need them.
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _write(key_path, _pem(key), 0o600)
    _write(cert_path, certificate.public_bytes(serialization.Encoding.PEM), 0o644)
    return folder


def issue(
    authority: str | Path,
    directory: str | Path,
    name: str,
    hosts: Iterable[str],
    *,
    renew: bool = False,
) -> Path:
    """A certificate for a component, as both server and client, for ``hosts``, in
    ``directory`` (``tls.crt``, ``tls.key``, ``ca.crt``); one there already is kept, unless
    ``renew``: then a new key and certificate replace it, which the component takes without
    a restart."""
    folder = Path(directory)
    if not renew and all((folder / f).exists() for f in (CERT, KEY, CA)):
        return folder
    ca_dir = Path(authority)
    ca_cert = x509.load_pem_x509_certificate((ca_dir / CA).read_bytes())
    ca_key = serialization.load_pem_private_key((ca_dir / "ca.key").read_bytes(), None)
    folder.mkdir(parents=True, exist_ok=True)
    key = _key()
    now = datetime.datetime.now(datetime.UTC)
    hosts = list(hosts)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CERTIFICATE_DAYS))
        .add_extension(x509.SubjectAlternativeName(_names(hosts or [name])), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]
    )
    _write(folder / KEY, _pem(key), 0o600)
    _write(folder / CERT, certificate.public_bytes(serialization.Encoding.PEM), 0o644)
    _write(folder / CA, (ca_dir / CA).read_bytes(), 0o644)
    return folder
