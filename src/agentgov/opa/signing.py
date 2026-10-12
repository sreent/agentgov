"""Signing OPA's bundles (https://www.openpolicyagent.org/docs/management-bundles#signing).

A signed bundle carries ``.signatures.json``: a JWT, signed with the control plane's key,
that lists every other file in the bundle with its SHA-256. OPA, configured with the
matching certificate or public key, checks the signature and each file before it activates
the bundle, and keeps enforcing the last good one when they don't match: whoever can reach
OPA, or the path to it, can't hand it policies or registry data of their own.

OPA hashes ``.rego`` files as they are, and JSON files (``data.json``, ``.manifest``) in a
canonical form: the content parsed, then written again with sorted keys, no spaces, and
strings as Go writes them (no HTML escaping, U+2028 and U+2029 escaped).
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

SIGNATURES = ".signatures.json"
CURVES = {"secp256r1": "ES256", "secp384r1": "ES384"}
CERTIFICATE_DAYS = 3650


class SigningError(ValueError):
    """The signing key can't be used; the message says why."""


def canonical(value: Any) -> str:
    """JSON as OPA writes it to hash a file."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def file_hash(name: str, content: str) -> str:
    if name.endswith(".json") or name.rsplit("/", 1)[-1] == ".manifest":
        return hashlib.sha256(canonical(json.loads(content)).encode()).hexdigest()
    return hashlib.sha256(content.encode()).hexdigest()


class Signer:
    """Signs bundles with a private key: RS256 for RSA, ES256 or ES384 for EC."""

    def __init__(self, pem: bytes, key_id: str) -> None:
        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except (ValueError, TypeError) as exc:
            raise SigningError(f"not a PEM private key without a passphrase: {exc}") from exc
        if isinstance(key, rsa.RSAPrivateKey):
            if key.key_size < 2048:
                raise SigningError("an RSA key needs at least 2048 bits")
            self.algorithm = "RS256"
        elif isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name in CURVES:
            self.algorithm = CURVES[key.curve.name]
        else:
            raise SigningError("the key must be RSA, or EC on P-256 or P-384")
        self.key = key
        self.key_id = key_id

    @classmethod
    def from_file(cls, path: str, key_id: str) -> Signer:
        try:
            pem = Path(path).read_bytes()
        except OSError as exc:
            raise SigningError(f"can't read {path}: {exc}") from exc
        return cls(pem, key_id)

    def signatures(self, files: dict[str, str]) -> str:
        """``.signatures.json`` for a bundle's files (by their path in the bundle)."""
        claims = {
            "files": [
                {"name": name, "hash": file_hash(name, content), "algorithm": "SHA-256"}
                for name, content in sorted(files.items())
            ],
            "keyid": self.key_id,
        }
        token = jwt.encode(claims, self.key, algorithm=self.algorithm, headers={"kid": self.key_id})
        return json.dumps({"signatures": [token]})


def generate(directory: str | Path, *, name: str = "AgentGov bundles") -> tuple[Path, Path]:
    """A new RSA key (``key.pem``) and a self-signed certificate for it (``cert.pem``, which
    OPA verifies with) in ``directory``; an existing pair is kept. Returns their paths."""
    folder = Path(directory)
    key_path, cert_path = folder / "key.pem", folder / "cert.pem"
    if key_path.exists() and cert_path.exists():
        return key_path, cert_path
    folder.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CERTIFICATE_DAYS))
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path
