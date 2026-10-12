"""Mutual TLS between AgentGov's components.

Each component (the control plane, the governance processor, OPA, agentgateway and the
OpenTelemetry Collector) holds a certificate from AgentGov's own certificate authority,
in a directory as cert-manager writes a certificate's Secret: ``tls.crt``, ``tls.key`` and
the authority's ``ca.crt`` (AGENTGOV_TLS_DIR). With them, a component serves TLS on its
internal ports and asks whoever calls for a certificate from the same authority, and it
presents its own when it calls another component. Nothing else on the network can pose
as the processor that decides on tool calls, or as OPA, or reach them.

``agentgov internal-certs DIR`` makes an authority and a certificate for each component,
where cert-manager isn't there to (Compose, or a cluster without it).
"""

from __future__ import annotations

import datetime
import ipaddress
import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT, KEY, CA = "tls.crt", "tls.key", "ca.crt"
CERTIFICATE_DAYS = 3650
# Marks a request that came in on the control plane's internal listener (asgi scope
# state), where every caller showed a certificate from AgentGov's authority.
INTERNAL = "agentgov.internal"


@dataclass(frozen=True)
class Identity:
    """A component's certificate, its key, and the authority it trusts."""

    cert: str
    key: str
    ca: str

    @classmethod
    def from_dir(cls, directory: str | Path) -> Identity:
        folder = Path(directory)
        found = cls(str(folder / CERT), str(folder / KEY), str(folder / CA))
        missing = [p for p in (found.cert, found.key, found.ca) if not Path(p).is_file()]
        if missing:
            raise ValueError(f"AGENTGOV_TLS_DIR lacks {', '.join(missing)}")
        return found

    def server_context(self) -> ssl.SSLContext:
        """For a server that asks every caller for a certificate from the authority."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.cert, self.key)
        context.load_verify_locations(self.ca)
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def client_context(self) -> ssl.SSLContext:
        """For calling another component: it checks theirs, and presents this one. Public
        services (an https:// URL elsewhere) are checked against the system's roots too."""
        context = ssl.create_default_context()
        context.load_verify_locations(self.ca)
        context.load_cert_chain(self.cert, self.key)
        return context

    def grpc_credentials(self) -> Any:
        import grpc

        return grpc.ssl_server_credentials(
            [(Path(self.key).read_bytes(), Path(self.cert).read_bytes())],
            root_certificates=Path(self.ca).read_bytes(),
            require_client_auth=True,
        )

    def uvicorn_options(self) -> dict[str, Any]:
        return {
            "ssl_certfile": self.cert,
            "ssl_keyfile": self.key,
            "ssl_ca_certs": self.ca,
            "ssl_cert_reqs": ssl.CERT_REQUIRED,
        }


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
    path.write_bytes(data)
    path.chmod(mode)


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
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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


def issue(authority: str | Path, directory: str | Path, name: str, hosts: Iterable[str]) -> Path:
    """A certificate for a component, as both server and client, for ``hosts``, in
    ``directory`` (``tls.crt``, ``tls.key``, ``ca.crt``); one there already is kept."""
    folder = Path(directory)
    if all((folder / f).exists() for f in (CERT, KEY, CA)):
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
