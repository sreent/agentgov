"""Delegation chains: who handed a call down to an agent, from agent to agent.

When an agent calls another through the gateway, AgentGov gives the agent it calls a
**delegation**, in the ``X-AgentGov-Delegation`` header: a short-lived token that says
who started the work (the person, when an agent acts for one) and which agents it
passed through. The called agent sends it back with the calls it makes for that work, to
tools, models and other agents, and AgentGov checks it: signed by AgentGov, not expired,
and given to the agent presenting it. Policy then sees the whole chain and the person at
its head, and the ledger records them, with each delegation's ID and its parent's, as
OCSF's delegation object has them.

The token is a JWT that AgentGov's processors sign and check with a key derived from the
service token (AGENTGOV_SERVICE_TOKEN), which agents never see. Like an OAuth
transaction token, it is only meaningful inside AgentGov's gateway: agents carry it
without reading it.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import jwt

HEADER = "x-agentgov-delegation"
ISSUER = "agentgov"
ALGORITHM = "HS256"
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
    """The key delegations are signed with, derived from the service token."""
    if not secret:
        return None
    return hmac.new(secret.encode(), b"agentgov-delegation-v1", hashlib.sha256).digest()


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
    key: bytes,
    *,
    links: list[dict[str, str]],
    audience: str,
    person: dict[str, Any] | None = None,
    parent: str | None = None,
    now: int | None = None,
) -> tuple[str, Chain]:
    """A delegation for the agent ``audience`` (its ID): ``links`` handed the call down."""
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
    token = jwt.encode(claims, key, algorithm=ALGORITHM)
    return token, Chain(uid=uid, links=links, person=person_claim, parent=parent, issued_at=issued)


def verify(key: bytes | None, token: str, *, holder: str | None) -> Chain:
    """The delegation ``token``, if AgentGov gave it to the agent ``holder`` (its ID)."""
    if key is None:
        raise ChainError("AgentGov can't check delegations: AGENTGOV_SERVICE_TOKEN is not set")
    if not holder:
        raise ChainError("the caller is not a registered agent, so it holds no delegation")
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[ALGORITHM],
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
