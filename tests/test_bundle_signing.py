"""Signed OPA bundles (agentgov.opa.signing): OPA itself verifies what the control plane
signs, and refuses a bundle anyone changed."""

from __future__ import annotations

import gzip
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from agentgov.config import Settings
from agentgov.opa import signing
from agentgov.registry import agents
from agentgov.runtime import Runtime
from tests.conftest import requires_opa

# What OPA's canonical JSON has to get right: HTML characters, non-ASCII, the line and
# paragraph separators, control characters.
AWKWARD = "José <ops> & co \u2028 \u2029 \x01\t\b"


def _files(body: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        return {m.name.lstrip("/"): tar.extractfile(m).read() for m in tar if m.isfile()}  # type: ignore[union-attr]


def _bundle(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w") as tar,
    ):
        for name, payload in sorted(files.items()):
            info = tarfile.TarInfo(name="/" + name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _verify(bundle: bytes, cert: Path, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "bundle.tar.gz"
    path.write_bytes(bundle)
    # opa build says why it refused a bundle on stdout.
    return subprocess.run(
        ["opa", "build", "--bundle", str(path), "--verification-key", str(cert),
         "--verification-key-id", "agentgov", "-o", str(tmp_path / "out.tar.gz")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False,
    )  # fmt: skip


@pytest.fixture
def signed(settings: Settings, tmp_path: Path) -> tuple[Runtime, Path]:
    key, cert = signing.generate(tmp_path / "keys")
    rt = Runtime(settings.with_overrides(bundle_signing_key_file=str(key)))
    rt.init_db()
    with rt.db.transaction() as tx:
        agents.register(
            tx, rt.settings, {"name": "support-bot", "owner": AWKWARD}, actor="admin:test"
        )
    yield rt, cert
    rt.db.dispose()


@requires_opa
def test_opa_verifies_what_the_control_plane_signs(
    signed: tuple[Runtime, Path], tmp_path: Path
) -> None:
    rt, cert = signed
    body = rt.bundles.current().body
    files = _files(body)
    assert signing.SIGNATURES in files
    registry = json.loads(files["registry/data.json"])
    assert [a["owner"] for a in registry["agents"].values()] == [AWKWARD]
    verified = _verify(body, cert, tmp_path)
    assert verified.returncode == 0, verified.stdout

    # Someone changes the registry data on the way: OPA refuses the bundle.
    data = json.loads(files["registry/data.json"])
    for agent in data["agents"].values():
        agent["status"] = "active"
    tampered = {**files, "registry/data.json": json.dumps(data).encode()}
    refused = _verify(_bundle(tampered), cert, tmp_path)
    assert refused.returncode != 0 and "digest mismatch" in refused.stdout

    # Or adds a policy of their own.
    extra = {**files, "agentgov/custom/mine.rego": b"package agentgov.custom.mine\n"}
    refused = _verify(_bundle(extra), cert, tmp_path)
    assert refused.returncode != 0 and "not included in bundle signature" in refused.stdout

    # Or signs it with another key.
    other, _ = signing.generate(tmp_path / "other")
    forged = signing.Signer(other.read_bytes(), "agentgov")
    unsigned = {k: v.decode() for k, v in files.items() if k != signing.SIGNATURES}
    resigned = {**files, signing.SIGNATURES: forged.signatures(unsigned).encode()}
    refused = _verify(_bundle(resigned), cert, tmp_path)
    assert refused.returncode != 0 and "verification error" in refused.stdout


def test_unsigned_without_a_key(rt: Runtime) -> None:
    assert signing.SIGNATURES not in _files(rt.bundles.current().body)


def test_the_keys_it_takes(tmp_path: Path) -> None:
    def pem(key: object) -> bytes:
        return key.private_bytes(  # type: ignore[attr-defined]
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    assert signing.Signer(pem(ec.generate_private_key(ec.SECP256R1())), "k").algorithm == "ES256"
    assert signing.Signer(pem(ec.generate_private_key(ec.SECP384R1())), "k").algorithm == "ES384"
    with pytest.raises(signing.SigningError, match="at least 2048 bits"):
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
        signing.Signer(pem(weak), "k")
    with pytest.raises(signing.SigningError, match="P-256 or P-384"):
        signing.Signer(pem(ec.generate_private_key(ec.SECP521R1())), "k")
    with pytest.raises(signing.SigningError, match="not a PEM private key"):
        signing.Signer(b"not a key", "k")
    with pytest.raises(signing.SigningError, match="can't read"):
        signing.Signer.from_file(str(tmp_path / "missing.pem"), "k")


def test_making_a_key_keeps_one_there(tmp_path: Path) -> None:
    key, cert = signing.generate(tmp_path)
    assert key.stat().st_mode & 0o777 == 0o600
    first = key.read_bytes()
    assert signing.generate(tmp_path) == (key, cert) and key.read_bytes() == first


def test_a_bad_key_stops_the_control_plane(settings: Settings, tmp_path: Path) -> None:
    (tmp_path / "bad.pem").write_text("nope")
    with pytest.raises(signing.SigningError):
        Runtime(settings.with_overrides(bundle_signing_key_file=str(tmp_path / "bad.pem")))
