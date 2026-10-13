"""RFC 3161 time-stamps for the ledger's checkpoints (docs/evidence.md).

A time-stamping authority signs the hash of what it is sent, with its own time. Sent a
checkpoint's statement (the chain's head at that checkpoint), its answer proves the chain
existed then, and that nothing before the checkpoint changed since: anyone can check it
with ``openssl ts -verify``, against the authority's certificate, without AgentGov.

The request and the parts of the answer AgentGov reads are small, fixed DER structures,
encoded and read here without an ASN.1 library: the request carries the statement's
SHA-256, a nonce, and asks for the authority's certificate. From the answer, AgentGov
reads the status, checks that the token covers the hash it sent, with its nonce, and that
the authority's signature on it verifies (CMS SignedData, RFC 5652): against the
authority's certificates (AGENTGOV_LEDGER_TSA_CA_FILE) when they are given, or else only
against the certificate the token carries, which shows that the token is whole, not who
signed it. It keeps the whole answer, signature and all, for whoever verifies it.
"""

from __future__ import annotations

import functools
import hashlib
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

QUERY = "application/timestamp-query"
REPLY = "application/timestamp-reply"
SEQUENCE, SET, INTEGER, OCTETS, OID, BOOLEAN, GENERALIZED_TIME = (
    0x30,
    0x31,
    0x02,
    0x04,
    0x06,
    0x01,
    0x18,
)
EXPLICIT_0, EXPLICIT_1, EXPLICIT_2 = 0xA0, 0xA1, 0xA2
IMPLICIT_0 = 0x80
STATUSES = {
    0: "granted",
    1: "granted with modifications",
    2: "rejection",
    3: "waiting",
    4: "revocation warning",
    5: "revocation notification",
}

SIGNED_DATA = "1.2.840.113549.1.7.2"
TST_INFO = "1.2.840.113549.1.9.16.1.4"
CONTENT_TYPE = "1.2.840.113549.1.9.3"
MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"
DIGESTS: dict[str, type[hashes.HashAlgorithm]] = {
    "1.3.14.3.2.26": hashes.SHA1,
    "2.16.840.1.101.3.4.2.4": hashes.SHA224,
    "2.16.840.1.101.3.4.2.1": hashes.SHA256,
    "2.16.840.1.101.3.4.2.2": hashes.SHA384,
    "2.16.840.1.101.3.4.2.3": hashes.SHA512,
}
# Signature algorithms, with the hash they name (None: the signer's digest algorithm).
RSA_SIGNATURES: dict[str, type[hashes.HashAlgorithm] | None] = {
    "1.2.840.113549.1.1.1": None,
    "1.2.840.113549.1.1.5": hashes.SHA1,
    "1.2.840.113549.1.1.14": hashes.SHA224,
    "1.2.840.113549.1.1.11": hashes.SHA256,
    "1.2.840.113549.1.1.12": hashes.SHA384,
    "1.2.840.113549.1.1.13": hashes.SHA512,
}
RSA_PSS = "1.2.840.113549.1.1.10"
EC_SIGNATURES: dict[str, type[hashes.HashAlgorithm] | None] = {
    "1.2.840.10045.2.1": None,
    "1.2.840.10045.4.1": hashes.SHA1,
    "1.2.840.10045.4.3.1": hashes.SHA224,
    "1.2.840.10045.4.3.2": hashes.SHA256,
    "1.2.840.10045.4.3.3": hashes.SHA384,
    "1.2.840.10045.4.3.4": hashes.SHA512,
}
ED25519 = "1.3.101.112"
# How many certificates, at most, lead from the authority's to one it is checked against.
MAX_CHAIN = 8


class TimestampError(Exception):
    """The authority couldn't be reached, refused, or answered something else."""


# ------------------------------------------------------------------------- DER


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def integer(n: int) -> bytes:
    return tlv(INTEGER, n.to_bytes(n.bit_length() // 8 + 1, "big"))


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        out += bytes(reversed(chunk))
    return tlv(OID, bytes(out))


SHA256 = tlv(SEQUENCE, oid("2.16.840.1.101.3.4.2.1") + b"\x05\x00")


@dataclass(frozen=True)
class _Node:
    tag: int
    start: int  # of its header
    value: int  # of its value
    end: int


def _read(data: bytes, pos: int) -> _Node:
    if pos + 2 > len(data):
        raise TimestampError("the authority's answer is cut short")
    tag, first, value = data[pos], data[pos + 1], pos + 2
    if first < 0x80:
        length = first
    else:
        size = first & 0x7F
        if not 0 < size <= 4:
            raise TimestampError("the authority's answer isn't DER")
        length = int.from_bytes(data[value : value + size], "big")
        value += size
    if value + length > len(data):
        raise TimestampError("the authority's answer is cut short")
    return _Node(tag, pos, value, value + length)


def _children(data: bytes, node: _Node) -> list[_Node]:
    out, pos = [], node.value
    while pos < node.end:
        child = _read(data, pos)
        out.append(child)
        pos = child.end
    return out


def _expect(node: _Node, tag: int, what: str) -> _Node:
    if node.tag != tag:
        raise TimestampError(f"the authority's answer has no {what} where expected")
    return node


def _int_value(data: bytes, node: _Node) -> int:
    return int.from_bytes(data[node.value : node.end], "big", signed=True)


def _oid_value(data: bytes, node: _Node) -> str:
    raw = data[_expect(node, OID, "object identifier").value : node.end]
    if not raw:
        raise TimestampError("the authority's answer has an empty object identifier")
    parts, value = [], 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    first = min(raw[0] // 40, 2)
    return ".".join(str(p) for p in [first, raw[0] - 40 * first, *parts])


def _der(data: bytes, node: _Node) -> bytes:
    return data[node.start : node.end]


# -------------------------------------------------------------- request, answer


def request(digest: bytes, nonce: int) -> bytes:
    """A TimeStampReq for a SHA-256 digest: version 1, the digest, a nonce, and the
    authority's certificate in the answer."""
    imprint = tlv(SEQUENCE, SHA256 + tlv(OCTETS, digest))
    return tlv(SEQUENCE, integer(1) + imprint + integer(nonce) + tlv(BOOLEAN, b"\xff"))


@dataclass(frozen=True)
class Stamp:
    """An authority's answer: the time it gives, and the whole answer (DER); and whether its
    signature was checked against the authority's certificates, rather than only against
    the certificate it carries."""

    time: datetime
    response: bytes
    authority: bool = False


@dataclass(frozen=True)
class Trust:
    """What time-stamps are checked against: the authority's certificates (a root, and
    any intermediate ones), from ``source``; none, or ``error`` when they can't be read."""

    roots: tuple[x509.Certificate, ...] = ()
    source: str | None = None
    error: str | None = None


def load_roots(path: str | Path) -> tuple[x509.Certificate, ...]:
    """The certificates in a PEM file (the authority's root, and any intermediate ones)."""
    try:
        roots = tuple(x509.load_pem_x509_certificates(Path(path).read_bytes()))
    except (OSError, ValueError) as exc:
        raise TimestampError(
            f"the authority's certificates in {path} can't be read: {exc}"
        ) from None
    if not roots:
        raise TimestampError(f"{path} holds no certificate")
    return roots


def trust(path: str | None) -> Trust:
    """The authority's certificates in ``path`` (AGENTGOV_LEDGER_TSA_CA_FILE), if set: read
    again when the file changes (the ledger is verified often)."""
    if not path:
        return Trust()
    try:
        found = os.stat(path)
    except OSError as exc:
        return Trust((), path, f"the authority's certificates in {path} can't be read: {exc}")
    return _trust(path, found.st_mtime_ns, found.st_size)


@functools.lru_cache(maxsize=4)
def _trust(path: str, _mtime: int, _size: int) -> Trust:
    try:
        return Trust(load_roots(path), path)
    except TimestampError as exc:
        return Trust((), path, str(exc))


def _gen_time(raw: bytes) -> datetime:
    text = raw.decode("ascii").rstrip("Z")
    whole, _, _fraction = text.partition(".")
    try:
        return datetime.strptime(whole, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        raise TimestampError(f"the authority's time {raw!r} isn't a GeneralizedTime") from None


def read_response(
    data: bytes,
    digest: bytes,
    nonce: int | None,
    *,
    roots: tuple[x509.Certificate, ...] | list[x509.Certificate] = (),
) -> Stamp:
    """Check a TimeStampResp: granted, for this digest and nonce, and signed by the
    authority (checked against ``roots``, its certificates, when given; else against the
    certificate the token carries). Returns its time."""
    try:
        return _read_response(data, digest, nonce, tuple(roots))
    except (IndexError, ValueError, UnicodeDecodeError) as exc:
        raise TimestampError(f"the authority's answer can't be read: {exc}") from None


def _read_response(
    data: bytes, digest: bytes, nonce: int | None, roots: tuple[x509.Certificate, ...]
) -> Stamp:
    resp = _expect(_read(data, 0), SEQUENCE, "TimeStampResp")
    parts = _children(data, resp)
    if not parts:
        raise TimestampError("the authority's answer is empty")
    status_info = _children(data, _expect(parts[0], SEQUENCE, "status"))
    status = _int_value(data, _expect(status_info[0], INTEGER, "status"))
    if status not in (0, 1):
        why = ""
        if len(status_info) > 1 and status_info[1].tag == SEQUENCE:
            texts = [
                data[t.value : t.end].decode("utf-8", "replace")
                for t in _children(data, status_info[1])
            ]
            why = f": {'; '.join(texts)}" if texts else ""
        name = STATUSES.get(status, f"status {status}")
        raise TimestampError(f"the authority refused it ({name}{why})")
    if len(parts) < 2:
        raise TimestampError("the authority granted it but sent no token")
    # ContentInfo { signedData, [0] SignedData { ..., encapContentInfo { tstInfo,
    # [0] OCTET STRING { TSTInfo } }, ... } }
    content = _children(data, _expect(parts[1], SEQUENCE, "token"))
    if _oid_value(data, content[0]) != SIGNED_DATA:
        raise TimestampError("the authority's token isn't signed data")
    signed = _children(data, _expect(_children(data, content[1])[0], SEQUENCE, "SignedData"))
    encap = _children(data, _expect(signed[2], SEQUENCE, "encapsulated content"))
    if _oid_value(data, encap[0]) != TST_INFO:
        raise TimestampError("the authority's token isn't a time-stamp")
    octets = _expect(
        _children(data, _expect(encap[1], EXPLICIT_0, "content"))[0], OCTETS, "TSTInfo"
    )
    info = _children(data, _expect(_read(data, octets.value), SEQUENCE, "TSTInfo"))
    imprint = _children(data, _expect(info[2], SEQUENCE, "message imprint"))
    hashed = _expect(imprint[1], OCTETS, "hashed message")
    if data[hashed.value : hashed.end] != digest:
        raise TimestampError("the authority time-stamped another hash than the one sent")
    when = _gen_time(data[_expect(info[4], GENERALIZED_TIME, "time").value : info[4].end])
    if nonce is not None:
        # After the time: accuracy (a SEQUENCE) and ordering (a BOOLEAN), maybe; the nonce.
        theirs = next((n for n in info[5:] if n.tag == INTEGER), None)
        if theirs is None or _int_value(data, theirs) != nonce:
            raise TimestampError("the authority's answer doesn't carry the nonce sent")
    authority = _check_signature(data, signed, data[octets.value : octets.end], when, roots)
    return Stamp(when, data, authority)


# ----------------------------------------------------------------- the signature


@dataclass(frozen=True)
class _Algorithm:
    oid: str
    params: _Node | None


def _algorithm(data: bytes, node: _Node) -> _Algorithm:
    parts = _children(data, _expect(node, SEQUENCE, "algorithm"))
    return _Algorithm(_oid_value(data, parts[0]), parts[1] if len(parts) > 1 else None)


def _hash(oid_: str) -> type[hashes.HashAlgorithm]:
    found = DIGESTS.get(oid_)
    if found is None:
        raise TimestampError(f"the authority uses a hash AgentGov doesn't check ({oid_})")
    return found


def _issuer_der(cert: x509.Certificate) -> bytes:
    """The issuer's name in ``cert``, as it is encoded there."""
    tbs = cert.tbs_certificate_bytes
    fields = _children(tbs, _read(tbs, 0))
    first = 1 if fields[0].tag == EXPLICIT_0 else 0  # the version, when not v1
    return _der(tbs, fields[first + 2])


def _signer(
    data: bytes, sid: _Node, certificates: list[x509.Certificate]
) -> x509.Certificate | None:
    """The certificate the signer info names, by issuer and serial number or by key ID."""
    if sid.tag == SEQUENCE:
        issuer, serial = _children(data, sid)[:2]
        name, number = _der(data, issuer), _int_value(data, serial)
        for cert in certificates:
            if cert.serial_number == number and _issuer_der(cert) == name:
                return cert
    elif sid.tag == IMPLICIT_0:
        key_id = data[sid.value : sid.end]
        for cert in certificates:
            try:
                ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            except x509.ExtensionNotFound:
                continue
            if ski.value.digest == key_id:
                return cert
    return None


def _attributes(data: bytes, node: _Node) -> dict[str, list[_Node]]:
    out: dict[str, list[_Node]] = {}
    for attribute in _children(data, node):
        kind, values = _children(data, _expect(attribute, SEQUENCE, "attribute"))[:2]
        out[_oid_value(data, kind)] = _children(data, _expect(values, SET, "attribute values"))
    return out


def _certificate_hash(data: bytes, attrs: dict[str, list[_Node]], cert: x509.Certificate) -> None:
    """The ESS signing-certificate attribute, when there is one, must name the certificate
    that signed (RFC 5035)."""
    der = cert.public_bytes(Encoding.DER)
    if SIGNING_CERTIFICATE_V2 in attrs:
        certs = _children(data, _children(data, attrs[SIGNING_CERTIFICATE_V2][0])[0])
        first = _children(data, certs[0])
        algorithm = hashes.SHA256
        if first[0].tag == SEQUENCE:
            algorithm = _hash(_algorithm(data, first[0]).oid)
            first = first[1:]
        expected = data[_expect(first[0], OCTETS, "certificate hash").value : first[0].end]
    elif SIGNING_CERTIFICATE in attrs:
        certs = _children(data, _children(data, attrs[SIGNING_CERTIFICATE][0])[0])
        first = _children(data, certs[0])
        algorithm = hashes.SHA1
        expected = data[_expect(first[0], OCTETS, "certificate hash").value : first[0].end]
    else:
        return
    digest = hashes.Hash(algorithm())
    digest.update(der)
    if digest.finalize() != expected:
        raise TimestampError(
            "the time-stamp names another certificate than the one it was signed with"
        )


def _pss(data: bytes, params: _Node | None) -> tuple[padding.PSS, hashes.HashAlgorithm]:
    """RSASSA-PSS parameters (RFC 4055): hash, mask generation, salt length."""
    algorithm: type[hashes.HashAlgorithm] = hashes.SHA1
    mgf: type[hashes.HashAlgorithm] = hashes.SHA1
    salt = 20
    for field in _children(data, params) if params is not None else []:
        inner = _children(data, field)[0]
        if field.tag == EXPLICIT_0:
            algorithm = _hash(_algorithm(data, inner).oid)
        elif field.tag == EXPLICIT_1:
            mask = _algorithm(data, inner)
            if mask.oid != "1.2.840.113549.1.1.8" or mask.params is None:
                raise TimestampError("the authority's RSASSA-PSS signature uses no MGF1")
            mgf = _hash(_algorithm(data, mask.params).oid)
        elif field.tag == EXPLICIT_2:
            salt = _int_value(data, inner)
    return padding.PSS(mgf=padding.MGF1(mgf()), salt_length=salt), algorithm()


def _verify(
    data: bytes,
    key: object,
    signature_algorithm: _Algorithm,
    digest: type[hashes.HashAlgorithm],
    signed: bytes,
    signature: bytes,
) -> None:
    kind = signature_algorithm.oid
    try:
        if isinstance(key, rsa.RSAPublicKey) and kind == RSA_PSS:
            pss, algorithm = _pss(data, signature_algorithm.params)
            key.verify(signature, signed, pss, algorithm)
        elif isinstance(key, rsa.RSAPublicKey) and kind in RSA_SIGNATURES:
            key.verify(signature, signed, padding.PKCS1v15(), (RSA_SIGNATURES[kind] or digest)())
        elif isinstance(key, ec.EllipticCurvePublicKey) and kind in EC_SIGNATURES:
            key.verify(signature, signed, ec.ECDSA((EC_SIGNATURES[kind] or digest)()))
        elif isinstance(key, ed25519.Ed25519PublicKey) and kind == ED25519:
            key.verify(signature, signed)
        else:
            raise TimestampError(
                f"the authority signs with an algorithm AgentGov doesn't check ({kind})"
            )
    except InvalidSignature:
        raise TimestampError("the authority's signature on the time-stamp doesn't verify") from None


def _valid_at(cert: x509.Certificate, when: datetime) -> None:
    if not cert.not_valid_before_utc <= when <= cert.not_valid_after_utc:
        raise TimestampError(
            f"the certificate of {cert.subject.rfc4514_string()} wasn't valid at the time the "
            "time-stamp gives"
        )


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    if cert.issuer != issuer.subject:
        return False
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        return False
    return True


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _anchor(
    signer: x509.Certificate,
    carried: list[x509.Certificate],
    roots: tuple[x509.Certificate, ...],
    when: datetime,
) -> None:
    """The signer's certificate leads to one of ``roots``, each link signed by the next and
    valid at the time the time-stamp gives."""
    current = signer
    for _ in range(MAX_CHAIN):
        if current in roots:
            return
        root = next((r for r in roots if _issued_by(current, r)), None)
        if root is not None:
            _valid_at(root, when)
            return
        issuer = next(
            (c for c in carried if c != current and _is_ca(c) and _issued_by(current, c)), None
        )
        if issuer is None:
            break
        _valid_at(issuer, when)
        current = issuer
    raise TimestampError(
        f"the certificate that signed it ({signer.subject.rfc4514_string()}) doesn't lead to "
        "the authority's certificates it is checked against"
    )


def _check_signature(
    data: bytes,
    signed: list[_Node],
    tst_info: bytes,
    when: datetime,
    roots: tuple[x509.Certificate, ...],
) -> bool:
    """The authority's signature on the token (RFC 5652, 5.4): over its signed attributes,
    which name the time-stamp's content and digest, with the certificate it names. Returns
    whether that certificate was checked against ``roots``, the authority's."""
    carried: list[x509.Certificate] = []
    infos: list[_Node] = []
    for node in signed[3:]:
        if node.tag == EXPLICIT_0:  # certificates [0] IMPLICIT
            carried += [
                x509.load_der_x509_certificate(_der(data, c))
                for c in _children(data, node)
                if c.tag == SEQUENCE
            ]
        elif node.tag == SET:
            infos = _children(data, node)
    if not infos:
        raise TimestampError("the time-stamp isn't signed")
    fields = _children(data, _expect(infos[0], SEQUENCE, "signer info"))
    digest = _hash(_algorithm(data, fields[2]).oid)
    rest = fields[3:]
    attrs_node = rest.pop(0) if rest and rest[0].tag == EXPLICIT_0 else None
    signature_algorithm = _algorithm(data, rest[0])
    signature = data[_expect(rest[1], OCTETS, "signature").value : rest[1].end]
    signer = _signer(data, fields[1], carried + list(roots))
    if signer is None:
        raise TimestampError(
            "the time-stamp doesn't carry the certificate it was signed with"
            + (", nor is it among the authority's certificates" if roots else "")
        )
    if attrs_node is not None:
        attrs = _attributes(data, attrs_node)
        kinds = attrs.get(CONTENT_TYPE) or []
        if len(kinds) != 1 or _oid_value(data, kinds[0]) != TST_INFO:
            raise TimestampError("the authority's signature isn't on a time-stamp")
        digests = attrs.get(MESSAGE_DIGEST) or []
        hashed = hashes.Hash(digest())
        hashed.update(tst_info)
        if len(digests) != 1 or data[digests[0].value : digests[0].end] != hashed.finalize():
            raise TimestampError("the authority's signature is on another time-stamp")
        _certificate_hash(data, attrs, signer)
        # Signed as a SET OF (RFC 5652, 5.4): the [0] IMPLICIT tag, retagged.
        covered = bytes([SET]) + data[attrs_node.start + 1 : attrs_node.end]
    else:
        covered = tst_info
    _verify(data, signer.public_key(), signature_algorithm, digest, covered, signature)
    try:
        purposes = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        purposes = None
    if purposes is None or ExtendedKeyUsageOID.TIME_STAMPING not in purposes:
        raise TimestampError("the certificate that signed it isn't for time-stamping")
    _valid_at(signer, when)
    if not roots:
        return False
    _anchor(signer, carried, roots, when)
    return True


def stamp(
    url: str,
    payload: bytes,
    http: httpx.Client | None = None,
    *,
    roots: tuple[x509.Certificate, ...] = (),
) -> Stamp:
    """Have the authority at ``url`` time-stamp ``payload`` (its SHA-256). An answer that
    doesn't check out is an error: nothing is kept, and it is asked again."""
    digest = hashlib.sha256(payload).digest()
    nonce = secrets.randbits(63)
    client = http or httpx.Client(timeout=30)
    try:
        resp = client.post(url, content=request(digest, nonce), headers={"Content-Type": QUERY})
    except httpx.HTTPError as exc:
        raise TimestampError(f"the time-stamping authority can't be reached: {exc}") from exc
    finally:
        if http is None:
            client.close()
    if resp.status_code != 200:
        raise TimestampError(f"the time-stamping authority answered HTTP {resp.status_code}")
    return read_response(resp.content, digest, nonce, roots=roots)
