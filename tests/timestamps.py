"""A time-stamping authority for the tests: RFC 3161 answers signed as an authority signs
them (CMS SignedData, ECDSA P-256), or forged without a signature."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from agentgov import timestamping as tsp

SIGNED_DATA = tsp.oid("1.2.840.113549.1.7.2")
TST_INFO = tsp.oid("1.2.840.113549.1.9.16.1.4")
CONTENT_TYPE = tsp.oid("1.2.840.113549.1.9.3")
MESSAGE_DIGEST = tsp.oid("1.2.840.113549.1.9.4")
SIGNING_CERTIFICATE_V2 = tsp.oid("1.2.840.113549.1.9.16.2.47")
ECDSA_SHA256 = tsp.tlv(0x30, tsp.oid("1.2.840.10045.4.3.2"))
GEN_TIME = b"20261011120000Z"


def _seq(*parts: bytes) -> bytes:
    return tsp.tlv(0x30, b"".join(parts))


def _set(*parts: bytes) -> bytes:
    # DER sorts a SET OF by the elements' encodings.
    return tsp.tlv(0x31, b"".join(sorted(parts)))


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _issuer_der(cert: x509.Certificate) -> bytes:
    data = cert.tbs_certificate_bytes
    fields = tsp._children(data, tsp._read(data, 0))
    first = 1 if fields[0].tag == 0xA0 else 0
    issuer = fields[first + 2]
    return data[issuer.start : issuer.end]


def tst_info(digest: bytes, nonce: int | None, gen_time: bytes = GEN_TIME) -> bytes:
    imprint = _seq(tsp.SHA256, tsp.tlv(0x04, digest))
    return _seq(
        tsp.integer(1),
        tsp.oid("1.2.3.4.1"),
        imprint,
        tsp.integer(7),
        tsp.tlv(0x18, gen_time),
        _seq(tsp.integer(1)),  # accuracy
        tsp.integer(nonce) if nonce is not None else b"",
    )


def _response(signed_data: bytes) -> bytes:
    content = _seq(SIGNED_DATA, tsp.tlv(0xA0, signed_data))
    return _seq(_seq(tsp.integer(0)), content)


def unsigned_reply(digest: bytes, nonce: int | None, gen_time: bytes = GEN_TIME) -> bytes:
    """A TimeStampResp anyone can write: the right imprint, and no signature."""
    info = tst_info(digest, nonce, gen_time)
    encap = _seq(TST_INFO, tsp.tlv(0xA0, tsp.tlv(0x04, info)))
    signed = _seq(tsp.integer(3), tsp.tlv(0x31, b""), encap, tsp.tlv(0x31, b""))
    return _response(signed)


def refusal(status: int) -> bytes:
    why = tsp.tlv(0x30, tsp.tlv(0x0C, b"unsupported algorithm"))
    return tsp.tlv(0x30, tsp.tlv(0x30, tsp.integer(status) + why))


class Authority:
    """A key and its certificate, for time-stamping (EKU timeStamping, critical): its own
    root, or issued by a root of its own (``chained``)."""

    def __init__(self, name: str = "Test TSA", *, chained: bool = False) -> None:
        now = datetime.now(UTC)
        self.key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(name))
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=3650))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
            )
        )
        if chained:
            self.root_key = ec.generate_private_key(ec.SECP256R1())
            self.root = (
                x509.CertificateBuilder()
                .subject_name(_name(f"{name} root"))
                .issuer_name(_name(f"{name} root"))
                .public_key(self.root_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=3650))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(self.root_key, hashes.SHA256())
            )
            self.cert = builder.issuer_name(self.root.subject).sign(self.root_key, hashes.SHA256())
        else:
            self.cert = builder.issuer_name(_name(name)).sign(self.key, hashes.SHA256())
            self.root = self.cert

    @property
    def pem(self) -> bytes:
        """What checks its time-stamps: its root's certificate."""
        return self.root.public_bytes(serialization.Encoding.PEM)

    def reply(
        self,
        digest: bytes,
        nonce: int | None,
        gen_time: bytes = GEN_TIME,
        *,
        carry: bool = True,
        tamper: bool = False,
    ) -> bytes:
        """A TimeStampResp for ``digest``, signed. ``carry``: with the certificate (as the
        request asks); ``tamper``: the time-stamp changed after it was signed."""
        info = tst_info(digest, nonce, gen_time)
        der = self.cert.public_bytes(serialization.Encoding.DER)
        attrs = [
            _seq(CONTENT_TYPE, _set(TST_INFO)),
            _seq(MESSAGE_DIGEST, _set(tsp.tlv(0x04, hashlib.sha256(info).digest()))),
            _seq(
                SIGNING_CERTIFICATE_V2,
                _set(_seq(_seq(_seq(tsp.tlv(0x04, hashlib.sha256(der).digest()))))),
            ),
        ]
        # Signed as a SET OF, carried as [0] IMPLICIT.
        content = b"".join(sorted(attrs))
        signature = self.key.sign(tsp.tlv(0x31, content), ec.ECDSA(hashes.SHA256()))
        if tamper:
            info = tst_info(digest, nonce, b"20200101000000Z")
        signer = _seq(
            tsp.integer(1),
            _seq(_issuer_der(self.cert), tsp.integer(self.cert.serial_number)),
            tsp.SHA256,
            tsp.tlv(0xA0, content),
            ECDSA_SHA256,
            tsp.tlv(0x04, signature),
        )
        encap = _seq(TST_INFO, tsp.tlv(0xA0, tsp.tlv(0x04, info)))
        certificates = tsp.tlv(0xA0, der) if carry else b""
        signed = _seq(tsp.integer(3), _set(tsp.SHA256), encap, certificates, _set(signer))
        return _response(signed)


_SHARED: Authority | None = None


def authority() -> Authority:
    """One authority for the tests that need any (making keys takes a moment)."""
    global _SHARED
    if _SHARED is None:
        _SHARED = Authority()
    return _SHARED


def query(data: bytes) -> tuple[bytes, int]:
    """The digest and nonce of a TimeStampReq."""
    req = tsp._children(data, tsp._read(data, 0))
    imprint = tsp._children(data, req[1])
    digest = data[imprint[1].value : imprint[1].end]
    return digest, tsp._int_value(data, req[2])


class FakeTSA:
    """An authority on the network: answers each request with a signed time-stamp, or
    refuses (``status``), forges (``forge``: no signature) or answers with the wrong
    nonce."""

    def __init__(self, signer: Authority | None = None) -> None:
        self.signer = signer or authority()
        self.status = 0
        self.wrong_nonce = False
        self.forge = False
        self.gen_time = GEN_TIME
        self.requests: list[bytes] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["content-type"] == tsp.QUERY
        self.requests.append(request.content)
        digest, nonce = query(request.content)
        nonce = nonce + 1 if self.wrong_nonce else nonce
        if self.status not in (0, 1):
            body = refusal(self.status)
        elif self.forge:
            body = unsigned_reply(digest, nonce, self.gen_time)
        else:
            body = self.signer.reply(digest, nonce, self.gen_time)
        return httpx.Response(200, content=body, headers={"content-type": tsp.REPLY})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))
