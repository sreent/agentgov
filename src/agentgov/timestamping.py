"""RFC 3161 time-stamps for the ledger's checkpoints (docs/evidence.md).

A time-stamping authority signs the hash of what it is sent, with its own time. Sent a
checkpoint's statement (the chain's head at that checkpoint), its answer proves the chain
existed then, and that nothing before the checkpoint changed since: anyone can check it
with ``openssl ts -verify``, against the authority's certificate, without AgentGov.

The request and the parts of the answer AgentGov reads are small, fixed DER structures,
encoded and read here without an ASN.1 library: the request carries the statement's
SHA-256, a nonce, and asks for the authority's certificate; from the answer, AgentGov
reads the status, and checks that the token covers the hash it sent, with its nonce. It
keeps the whole answer, signature and all, for whoever verifies it.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

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
EXPLICIT_0 = 0xA0
STATUSES = {
    0: "granted",
    1: "granted with modifications",
    2: "rejection",
    3: "waiting",
    4: "revocation warning",
    5: "revocation notification",
}


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


# -------------------------------------------------------------- request, answer


def request(digest: bytes, nonce: int) -> bytes:
    """A TimeStampReq for a SHA-256 digest: version 1, the digest, a nonce, and the
    authority's certificate in the answer."""
    imprint = tlv(SEQUENCE, SHA256 + tlv(OCTETS, digest))
    return tlv(SEQUENCE, integer(1) + imprint + integer(nonce) + tlv(BOOLEAN, b"\xff"))


@dataclass(frozen=True)
class Stamp:
    """An authority's answer: the time it gives, and the whole answer (DER)."""

    time: datetime
    response: bytes


def _gen_time(raw: bytes) -> datetime:
    text = raw.decode("ascii").rstrip("Z")
    whole, _, _fraction = text.partition(".")
    try:
        return datetime.strptime(whole, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        raise TimestampError(f"the authority's time {raw!r} isn't a GeneralizedTime") from None


def read_response(data: bytes, digest: bytes, nonce: int | None) -> Stamp:
    """Check a TimeStampResp: granted, for this digest and nonce; returns its time."""
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
    signed = _children(data, _expect(_children(data, content[1])[0], SEQUENCE, "SignedData"))
    encap = _children(data, _expect(signed[2], SEQUENCE, "encapsulated content"))
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
    return Stamp(when, data)


def stamp(url: str, payload: bytes, http: httpx.Client | None = None) -> Stamp:
    """Have the authority at ``url`` time-stamp ``payload`` (its SHA-256)."""
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
    return read_response(resp.content, digest, nonce)
