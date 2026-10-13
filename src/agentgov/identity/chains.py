"""Delegation chains: who handed a call down to an agent, from agent to agent.

When an agent calls another through the gateway, AgentGov gives the agent it calls a
**delegation**, in the ``X-AgentGov-Delegation`` header: a short-lived token that says
who started the work (the person, when an agent acts for one) and which agents it
passed through. The called agent sends it back with the calls it makes for that work, to
tools, models and other agents, and AgentGov checks it: signed by AgentGov, not expired,
and given to the agent presenting it. Policy then sees the whole chain and the person at
its head, and the ledger records them, with each delegation's ID and its parent's, as
OCSF's delegation object has them.

The token is a JWT that AgentGov's processors sign (ES256) with a key derived from the
signing secret (AGENTGOV_SIGNING_SECRET, or else the service token), which agents never
see; the control plane publishes the key's public half (GET /v1/delegations/jwks). Agents
carry it without reading it, like an OAuth transaction token. An agent may check it, too:
a call with a delegation AgentGov gave it came through the gateway, and one without came
around it, so an agent that refuses those takes only calls AgentGov checked
(docs/agent-to-agent.md#calls-around-the-gateway). Delegations signed before (HS256, with
a key derived the same way) are accepted until they expire.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

HEADER = "x-agentgov-delegation"
ISSUER = "agentgov"
ALGORITHM = "ES256"
# How delegations were signed before agents could check them: still checked, for those
# given before an upgrade (they expire within the hour); a later release can drop it.
LEGACY_ALGORITHM = "HS256"
# The order of P-256's group: a private key is a number below it.
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
# Long enough for an agent to finish what it was asked; a new call starts a new one.
TTL_SECONDS = 3600
MAX_LINKS = 16
# What the gateway hands the called agent, beside the delegation (readable, informative).
CALLER_HEADER = "x-agentgov-caller"
PERSON_HEADER = "x-agentgov-on-behalf-of"
CHAIN_HEADER = "x-agentgov-chain"


class ChainError(Exception):
    """A delegation that can't be used (forged, expired, or someone else's)."""


@dataclass(frozen=True)
class Chain:
    """A delegation: who handed the call down, in order, and the person at its head."""

    uid: str
    links: list[dict[str, str]] = field(default_factory=list)
    person: dict[str, Any] | None = None
    parent: str | None = None
    issued_at: int = 0

    def describe(self, *more: dict[str, str]) -> str:
        return describe([*self.links, *more])


def signing_key(secret: str | None) -> bytes | None:
    """The key delegations were signed with before (HS256), derived from ``secret``."""
    if not secret:
        return None
    return hmac.new(secret.encode(), b"agentgov-delegation-v1", hashlib.sha256).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass(frozen=True)
class Keys:
    """What AgentGov signs delegations with: a P-256 key, derived from the signing secret
    (or the service token) so that every processor holds the same one, whose public half the
    control plane publishes; and the key it signed them with before, to check those until
    they expire."""

    private: ec.EllipticCurvePrivateKey
    legacy: bytes

    @property
    def public(self) -> ec.EllipticCurvePublicKey:
        return self.private.public_key()

    def jwk(self) -> dict[str, str]:
        """The public key as a JWK, its ID the key's thumbprint (RFC 7638)."""
        return public_jwk(self.public)

    @property
    def kid(self) -> str:
        return self.jwk()["kid"]


def public_jwk(public: ec.EllipticCurvePublicKey) -> dict[str, str]:
    """A P-256 public key as a JWK for ES256, its ID the key's thumbprint (RFC 7638)."""
    numbers = public.public_numbers()
    key = {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64(numbers.x.to_bytes(32, "big")),
        "y": _b64(numbers.y.to_bytes(32, "big")),
    }
    canonical = json.dumps(key, sort_keys=True, separators=(",", ":")).encode()
    kid = _b64(hashlib.sha256(canonical).digest())
    return {**key, "kid": kid, "alg": ALGORITHM, "use": "sig"}


def derive_key(secret: str, purpose: bytes) -> ec.EllipticCurvePrivateKey:
    """A P-256 key derived from a secret, one for each purpose, so that every component
    that holds the secret holds the same key."""
    seed = hmac.new(secret.encode(), purpose, hashlib.sha256).digest()
    scalar = int.from_bytes(seed, "big") % (_P256_ORDER - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def keys(secret: str | None) -> Keys | None:
    """The keys delegations are signed and checked with, derived from ``secret``: the
    signing secret, or else the service token (None without either)."""
    legacy = signing_key(secret)
    if not secret or legacy is None:
        return None
    return Keys(private=derive_key(secret, b"agentgov-delegation-es256-v1"), legacy=legacy)


def jwks(found: Keys | None) -> dict[str, Any]:
    """The public keys agents check delegations with (a JSON Web Key Set)."""
    return {"keys": [found.jwk()] if found is not None else []}


def link(kind: str, ident: Any, name: Any) -> dict[str, str]:
    return {"type": kind, "id": str(ident or name or ""), "name": str(name or ident or "")}


def person_link(person: dict[str, Any]) -> dict[str, str]:
    name = person.get("username") or person.get("email") or person.get("id")
    return link("person", person.get("id"), name)


def describe(links: list[dict[str, str]]) -> str:
    return " > ".join(entry.get("name") or entry.get("id") or "?" for entry in links)


def _person_claim(person: dict[str, Any] | None) -> dict[str, Any] | None:
    if not person:
        return None
    keep = ("id", "username", "email", "groups", "roles", "via")
    return {k: person[k] for k in keep if person.get(k) not in (None, "", [])}


def issue(
    found: Keys,
    *,
    links: list[dict[str, str]],
    audience: str | list[str],
    person: dict[str, Any] | None = None,
    parent: str | None = None,
    now: int | None = None,
) -> tuple[str, Chain]:
    """A delegation for the agent ``audience`` (its ID, and its name: either names it to
    an agent checking it): ``links`` handed the call down."""
    if len(links) > MAX_LINKS:
        raise ChainError(f"a chain holds at most {MAX_LINKS} links")
    issued = int(now if now is not None else time.time())
    uid = "dlg_" + secrets.token_hex(12)
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": audience,
        "jti": uid,
        "iat": issued,
        "exp": issued + TTL_SECONDS,
        "chain": links,
    }
    if parent:
        claims["parent"] = parent
    person_claim = _person_claim(person)
    if person_claim:
        claims["person"] = person_claim
    token = jwt.encode(claims, found.private, algorithm=ALGORITHM, headers={"kid": found.kid})
    return token, Chain(uid=uid, links=links, person=person_claim, parent=parent, issued_at=issued)


def verify(found: Keys | None, token: str, *, holder: str | None) -> Chain:
    """The delegation ``token``, if AgentGov gave it to the agent ``holder`` (its ID)."""
    if found is None:
        raise ChainError("AgentGov can't check delegations: AGENTGOV_SERVICE_TOKEN is not set")
    if not holder:
        raise ChainError("the caller is not a registered agent, so it holds no delegation")
    try:
        algorithm = jwt.get_unverified_header(token).get("alg")
    except jwt.InvalidTokenError:
        raise ChainError("the delegation it carries isn't one AgentGov gave") from None
    if algorithm not in (ALGORITHM, LEGACY_ALGORITHM):
        raise ChainError("the delegation it carries isn't one AgentGov gave")
    key: Any = found.public if algorithm == ALGORITHM else found.legacy
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            audience=holder,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "jti", "aud", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise ChainError("the delegation it carries has expired") from None
    except jwt.InvalidAudienceError:
        raise ChainError("the delegation it carries was given to another agent") from None
    except jwt.InvalidTokenError:
        raise ChainError("the delegation it carries isn't one AgentGov gave") from None
    links = claims.get("chain")
    if not isinstance(links, list) or not all(isinstance(x, dict) for x in links):
        raise ChainError("the delegation it carries isn't one AgentGov gave")
    person = claims.get("person") if isinstance(claims.get("person"), dict) else None
    return Chain(
        uid=str(claims["jti"]),
        links=[{k: str(v) for k, v in entry.items()} for entry in links],
        person=person,
        parent=claims.get("parent"),
        issued_at=int(claims["iat"]),
    )


def same_person(a: dict[str, Any] | None, b: dict[str, Any] | None) -> bool:
    if not a or not b:
        return True
    return str(a.get("id")) == str(b.get("id"))
