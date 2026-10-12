"""Ledger checkpoints in a transparency log: Sigstore's Rekor (v2), docs/evidence.md.

A time-stamping authority proves that a checkpoint existed at a time. A transparency log
proves that it was published where anyone can see it, in a log that only grows: AgentGov
can't show one assessor a checkpoint and another a different one for the same entry
without the log holding both. With ``AGENTGOV_LEDGER_REKOR_URL`` set, AgentGov signs each
checkpoint's statement (the one the authority stamps) with a key of its own, ECDSA P-256
(``AGENTGOV_LEDGER_REKOR_SIGNING_KEY_FILE``), and adds it to the log as a hashedrekord
entry. The log answers with the entry, its index, and a proof that the entry is in the
tree its signed checkpoint describes. AgentGov keeps the answer as it came, checks it with
the log's public key (``AGENTGOV_LEDGER_REKOR_LOG_KEY_FILE``), and hands it to assessors
as a Sigstore bundle, which verifies offline: with ``agentgov ledger verify-log-entry``,
or with cosign (``cosign verify-blob --key ... --bundle ... --trusted-root ...``).

What the log publishes, for good: the statement's SHA-256, which says nothing about the
ledger, the signature, and AgentGov's public key, which ties the entries together (who
watches the log sees how often AgentGov adds one). Use Sigstore's public log or one of
your own (rekor-tiles).

Rekor v2 (https://github.com/sigstore/rekor-tiles): ``POST /api/v2/log/entries`` takes a
``hashedRekordRequestV002``; its checkpoints are C2SP signed notes
(https://c2sp.org/signed-note, https://c2sp.org/tlog-checkpoint), its proofs RFC 6962's.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

ENTRIES = "/api/v2/log/entries"
KEY_DETAILS = "PKIX_ECDSA_P256_SHA_256"
# The log answers once its next checkpoint, which holds the entry, is published.
TIMEOUT = 30.0
BUNDLE = "application/vnd.dev.sigstore.bundle.v0.3+json"
TRUSTED_ROOT = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"


class TransparencyError(Exception):
    """The log didn't take the entry, or its answer doesn't prove it holds it."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(value: Any, what: str) -> bytes:
    try:
        return base64.b64decode(str(value), validate=True)
    except ValueError:
        raise TransparencyError(f"the log's answer has a {what} that isn't base64") from None


# ------------------------------------------------------------------------ keys


def load_signing_key(path: str | Path) -> ec.EllipticCurvePrivateKey:
    """AgentGov's key for the log: an ECDSA P-256 private key, PEM, without a passphrase."""
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise TransparencyError(f"the signing key in {path} can't be read: {exc}") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise TransparencyError(f"the signing key in {path} isn't an ECDSA P-256 key")
    return key


def load_log_key(path: str | Path) -> ed25519.Ed25519PublicKey:
    """The log's public key (PEM): Ed25519, as Rekor v2's logs sign their checkpoints."""
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise TransparencyError(f"the log's key in {path} can't be read: {exc}") from None
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TransparencyError(f"the log's key in {path} isn't an Ed25519 public key")
    return key


def public_pem(
    key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey,
) -> bytes:
    public = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _spki(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def generate(directory: str | Path) -> tuple[Path, Path]:
    """A signing key for the log (key.pem) and its public half (public.pem), in
    ``directory``; a pair already there is kept."""
    folder = Path(directory)
    key_file, public_file = folder / "key.pem", folder / "public.pem"
    if key_file.exists():
        key = load_signing_key(key_file)
    else:
        folder.mkdir(parents=True, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_file.chmod(0o600)
    public_file.write_bytes(public_pem(key))
    return key_file, public_file


def generate_log_key(directory: str | Path) -> tuple[Path, Path]:
    """A key for a transparency log of your own (rekor-tiles' --signer-filepath): Ed25519,
    log.pem, and its public half, log.pub, for AGENTGOV_LEDGER_REKOR_LOG_KEY_FILE; a key
    already there is kept."""
    folder = Path(directory)
    key_file, public_file = folder / "log.pem", folder / "log.pub"
    if key_file.exists():
        try:
            key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        except (ValueError, TypeError) as exc:
            raise TransparencyError(f"the log key in {key_file} can't be read: {exc}") from None
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise TransparencyError(f"the log key in {key_file} isn't an Ed25519 key")
    else:
        folder.mkdir(parents=True, exist_ok=True)
        key = ed25519.Ed25519PrivateKey.generate()
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_file.chmod(0o600)
    public_file.write_bytes(public_pem(key.public_key()))
    return key_file, public_file


def origin_of(url: str) -> str:
    """A log's name in its checkpoints, by default: its URL's host name."""
    return urlsplit(url).hostname or url


# ----------------------------------------------------------------------- adding


def _signed(statement: bytes, key: ec.EllipticCurvePrivateKey) -> tuple[bytes, bytes]:
    digest = hashlib.sha256(statement).digest()
    return digest, key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def request(statement: bytes, key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    """The entry for ``statement``: its SHA-256, signed with ``key`` (a hashedrekord)."""
    digest, signature = _signed(statement, key)
    return {
        "hashedRekordRequestV002": {
            "digest": _b64(digest),
            "signature": {
                "content": _b64(signature),
                "verifier": {
                    "publicKey": {"rawBytes": _b64(_spki(key.public_key()))},
                    "keyDetails": KEY_DETAILS,
                },
            },
        }
    }


def add(
    url: str,
    statement: bytes,
    key: ec.EllipticCurvePrivateKey,
    *,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """Add ``statement`` to the log at ``url``; its answer, a TransparencyLogEntry. Each
    signature is new (ECDSA), so a try again after a failure adds an entry of its own
    rather than meeting the one before (which the log would refuse, without its proof)."""
    client = http or httpx.Client(timeout=TIMEOUT)
    try:
        resp = client.post(url.rstrip("/") + ENTRIES, json=request(statement, key))
    except httpx.HTTPError as exc:
        raise TransparencyError(f"the log at {url} can't be reached: {exc}") from None
    finally:
        if http is None:
            client.close()
    if resp.status_code not in (200, 201):
        raise TransparencyError(
            f"the log at {url} didn't take the entry (HTTP {resp.status_code}): {resp.text[:300]}"
        )
    try:
        entry = resp.json()
        int(entry["logIndex"])
        str(entry["inclusionProof"]["checkpoint"]["envelope"])
        str(entry["canonicalizedBody"])
    except (ValueError, KeyError, TypeError):
        raise TransparencyError(
            f"the log at {url} answered something else: {resp.text[:300]}"
        ) from None
    return entry


# ------------------------------------------------------------------- checking


@dataclass(frozen=True)
class Checked:
    """What an entry's proof shows: its index, in the tree of this size and root, which
    the log named ``origin`` signed."""

    index: int
    tree_size: int
    root_hash: str
    origin: str


def note_key_id(origin: str, log_key: ed25519.Ed25519PublicKey) -> bytes:
    """A signed note's key ID for an Ed25519 key (C2SP signed-note), all 32 bytes."""
    raw = log_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(origin.encode() + b"\n\x01" + raw).digest()


def check_checkpoint(
    envelope: str, *, origin: str, log_key: ed25519.Ed25519PublicKey
) -> tuple[int, bytes]:
    """The tree size and root hash of a checkpoint the log signed; TransparencyError when
    the log didn't sign it."""
    text, blank, signatures = envelope.partition("\n\n")
    if not blank:
        raise TransparencyError("the log's checkpoint isn't a signed note")
    body = (text + "\n").encode()
    key_id = note_key_id(origin, log_key)[:4]
    signed = False
    for line in signatures.splitlines():
        if not line.startswith("— "):
            continue
        name, _, value = line[2:].rpartition(" ")
        blob = _unb64(value, "checkpoint signature")
        if name != origin or blob[:4] != key_id:
            continue  # a witness's co-signature, or another key's
        try:
            log_key.verify(blob[4:], body)
        except InvalidSignature:
            raise TransparencyError("the log's checkpoint signature doesn't verify") from None
        signed = True
    if not signed:
        raise TransparencyError(f"the checkpoint isn't signed by the log {origin} with its key")
    lines = text.split("\n")
    if len(lines) < 3 or lines[0] != origin:
        raise TransparencyError(f"the checkpoint is for another log ({lines[0]!r})")
    try:
        return int(lines[1]), _unb64(lines[2], "root hash")
    except ValueError:
        raise TransparencyError("the checkpoint's tree size isn't a number") from None


def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def root_from_proof(index: int, size: int, leaf: bytes, proof: list[bytes]) -> bytes:
    """The root an inclusion proof leads to (RFC 6962 section 2.1.1, RFC 9162 2.1.3.2)."""
    if not 0 <= index < size:
        raise TransparencyError(f"the entry's index {index} isn't in a tree of {size}")
    inner = (index ^ (size - 1)).bit_length()
    border = bin(index >> inner).count("1")
    if len(proof) != inner + border:
        raise TransparencyError("the inclusion proof has the wrong number of hashes")
    node = leaf
    for i, sibling in enumerate(proof[:inner]):
        node = _node(node, sibling) if (index >> i) & 1 == 0 else _node(sibling, node)
    for sibling in proof[inner:]:
        node = _node(sibling, node)
    return node


def check(
    entry: dict[str, Any],
    statement: bytes,
    *,
    log_key: ed25519.Ed25519PublicKey,
    origin: str,
    signer: ec.EllipticCurvePublicKey | None = None,
) -> Checked:
    """That the log holds ``statement``, signed by ``signer`` (AgentGov's key, if given):
    its checkpoint is signed with ``log_key``, the entry is in its tree, and the entry is
    ``statement``'s digest with a signature that verifies. Offline: no call to the log."""
    try:
        proof = entry["inclusionProof"]
        index = int(entry["logIndex"])
        hashes_ = [_unb64(h, "proof hash") for h in proof.get("hashes") or []]
        envelope = str(proof["checkpoint"]["envelope"])
        body = _unb64(entry["canonicalizedBody"], "body")
    except (KeyError, TypeError, ValueError):
        raise TransparencyError("the log entry is missing its proof") from None
    size, root = check_checkpoint(envelope, origin=origin, log_key=log_key)
    if root_from_proof(index, size, _leaf(body), hashes_) != root:
        raise TransparencyError("the entry isn't in the tree the log's checkpoint describes")
    try:
        spec = json.loads(body)["spec"]["hashedRekordV002"]
        digest = _unb64(spec["data"]["digest"], "digest")
        signature = _unb64(spec["signature"]["content"], "signature")
        der = _unb64(spec["signature"]["verifier"]["publicKey"]["rawBytes"], "key")
        algorithm = spec["data"].get("algorithm", "SHA2_256")
    except (KeyError, TypeError, ValueError):
        raise TransparencyError("the entry isn't a hashedrekord (v0.0.2)") from None
    if algorithm != "SHA2_256" or digest != hashlib.sha256(statement).digest():
        raise TransparencyError("the entry is for another statement")
    key = serialization.load_der_public_key(der)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TransparencyError("the entry's key isn't an ECDSA key")
    if signer is not None and _spki(key) != _spki(signer):
        raise TransparencyError("the entry was signed with another key than AgentGov's")
    try:
        key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except InvalidSignature:
        raise TransparencyError("the entry's signature doesn't verify") from None
    return Checked(index=index, tree_size=size, root_hash=root.hex(), origin=origin)


# ------------------------------------------------- for assessors: Sigstore's formats


def signer_of(entry: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """The key an entry was signed with, as the log holds it."""
    try:
        body = json.loads(_unb64(entry["canonicalizedBody"], "body"))
        der = body["spec"]["hashedRekordV002"]["signature"]["verifier"]["publicKey"]["rawBytes"]
        key = serialization.load_der_public_key(_unb64(der, "key"))
    except (KeyError, TypeError, ValueError):
        raise TransparencyError("the entry isn't a hashedrekord (v0.0.2)") from None
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TransparencyError("the entry's key isn't an ECDSA key")
    return key


def bundle(entry: dict[str, Any], statement: bytes) -> dict[str, Any]:
    """The entry as a Sigstore bundle (v0.3, signed with a key rather than a certificate),
    for ``cosign verify-blob --key agentgov.pub --bundle ... --trusted-root ...``."""
    body = json.loads(_unb64(entry["canonicalizedBody"], "body"))
    signature = body["spec"]["hashedRekordV002"]["signature"]["content"]
    tlog = {k: v for k, v in entry.items() if v is not None}
    return {
        "mediaType": BUNDLE,
        "verificationMaterial": {
            "publicKey": {"hint": hashlib.sha256(_spki(signer_of(entry))).hexdigest()},
            "tlogEntries": [tlog],
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": _b64(hashlib.sha256(statement).digest()),
            },
            "signature": signature,
        },
    }


def trusted_root(url: str, origin: str, log_key: ed25519.Ed25519PublicKey) -> dict:
    """The log as Sigstore's verifiers trust it (a trusted root with that log alone)."""
    key_id = _b64(note_key_id(origin, log_key))
    der = log_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "mediaType": TRUSTED_ROOT,
        "tlogs": [
            {
                "baseUrl": url.rstrip("/"),
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": _b64(der),
                    "keyDetails": "PKIX_ED25519",
                    "validFor": {"start": "2020-01-01T00:00:00Z"},
                },
                "logId": {"keyId": key_id},
                "checkpointKeyId": {"keyId": key_id},
            }
        ],
        "certificateAuthorities": [],
        "ctlogs": [],
        "timestampAuthorities": [],
    }
