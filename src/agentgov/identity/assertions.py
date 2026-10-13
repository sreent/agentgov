"""Identity assertions (ID-JAG) for MCP servers outside the gateway: AgentGov as the
enterprise's issuer in MCP's enterprise-managed authorization
(docs/acting-for-people.md#mcp-servers-outside-the-gateway).

Some MCP servers aren't behind AgentGov's gateway: they take access tokens from an
authorization server of their own. MCP's enterprise-managed authorization lets the
enterprise decide which of them people's clients and agents may reach: the client trades
a token it has for an Identity Assertion JWT Authorization Grant (an ID-JAG,
draft-ietf-oauth-identity-assertion-authz-grant) from the enterprise's issuer, and the
ID-JAG at the server's authorization server for an access token (RFC 7523).

Keycloak can't issue ID-JAGs (it can take them, as an experimental feature), so AgentGov
does, while the identity-assertions feature is on:

* an agent asks AgentGov's token endpoint (``POST /oauth2/token``, OAuth 2.0 Token
  Exchange, RFC 8693) with the token it has for the gateway, its own or one it got for a
  person, for the server's authorization server (``audience``) and the server
  (``resource``);
* AgentGov checks the token with Keycloak's keys, finds the tool server registered with
  that authorization server, and asks its policies (``data.agentgov.idjag.decision``)
  whether the agent may reach it, for that person: the agent's grants on the server, whom
  its blueprint lets it act for, its risk;
* the ID-JAG (``typ`` ``oauth-id-jag+jwt``, at most five minutes) names the person, or
  the agent acting on its own (``sub``), the authorization server (``aud``), the client
  the agent is there (``client_id``), the server (``resource``), and the agent
  (``act``); AgentGov signs it with a P-256 key it derives from the signing secret (or
  else the service token) and publishes (``/oauth2/jwks``). Every assertion given, or
  refused, is in the ledger.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from agentgov.identity import chains, people

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 - a grant type
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
ID_JAG = "urn:ietf:params:oauth:token-type:id-jag"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 - a token type
ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"  # noqa: S105 - a token type
SUBJECT_TOKEN_TYPES = (ACCESS_TOKEN, ID_TOKEN)
TYP = "oauth-id-jag+jwt"
# What an authorization server that takes ID-JAGs advertises (authorization_grant_profiles_
# supported in its metadata).
GRANT_PROFILE = "urn:ietf:params:oauth:grant-profile:id-jag"
MAX_LIFETIME = 300
TOKEN_PATH = "/oauth2/token"  # noqa: S105 - a path
JWKS_PATH = "/oauth2/jwks"
METADATA_PATH = "/.well-known/oauth-authorization-server"
# The algorithms Keycloak signs tokens with that AgentGov takes.
SUBJECT_ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"]
KEYS_REFETCH_SECONDS = 30


class Refused(Exception):
    """A token request AgentGov won't grant, as the token endpoint answers it (RFC 6749
    section 5.2; RFC 8693 adds invalid_target)."""

    def __init__(self, error: str, description: str, status: int = 400) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status

    def body(self) -> dict[str, str]:
        return {"error": self.error, "error_description": self.description}


# ----------------------------------------------------------------- AgentGov's key


def signing_key(secret: str | None) -> ec.EllipticCurvePrivateKey | None:
    """The key AgentGov signs ID-JAGs with, derived from ``secret``: the signing secret, or
    else the service token (None without either); apart from the one it signs delegations
    with."""
    return chains.derive_key(secret, b"agentgov-id-jag-es256-v1") if secret else None


def jwks(key: ec.EllipticCurvePrivateKey | None) -> dict[str, Any]:
    """The public key authorization servers check ID-JAGs with (a JSON Web Key Set)."""
    return {"keys": [chains.public_jwk(key.public_key())] if key is not None else []}


def metadata(issuer: str) -> dict[str, Any]:
    """AgentGov's metadata as the issuer of ID-JAGs (RFC 8414)."""
    base = issuer.rstrip("/")
    return {
        "issuer": issuer,
        "token_endpoint": base + TOKEN_PATH,
        "jwks_uri": base + JWKS_PATH,
        "grant_types_supported": [TOKEN_EXCHANGE],
        # The token an agent brings authenticates it: no client secret.
        "token_endpoint_auth_methods_supported": ["none"],
        "response_types_supported": [],
        # What a token exchange gives (OAuth identity and authorization chaining).
        "identity_chaining_requested_token_types_supported": [ID_JAG],
    }


# ------------------------------------------------------------------- the request


@dataclass(frozen=True)
class Request:
    """A token exchange that asks for an ID-JAG."""

    subject_token: str
    subject_token_type: str
    audience: str
    resource: str | None = None
    scope: str | None = None


def form(body: bytes) -> dict[str, list[str]]:
    """An application/x-www-form-urlencoded body's fields."""
    try:
        return parse_qs(body.decode(), keep_blank_values=True, strict_parsing=False)
    except UnicodeDecodeError:
        raise Refused("invalid_request", "the request isn't a form in UTF-8") from None


def parse(fields: Mapping[str, list[str]]) -> Request:
    """The request, from the token endpoint's form fields."""

    def one(name: str, *, required: bool = True) -> str | None:
        values = [v for v in fields.get(name) or [] if v]
        if len(values) > 1:
            raise Refused("invalid_request", f"{name} is given more than once")
        if not values:
            if required:
                raise Refused("invalid_request", f"{name} is missing")
            return None
        return values[0]

    grant = one("grant_type")
    if grant != TOKEN_EXCHANGE:
        raise Refused("unsupported_grant_type", f"AgentGov's token endpoint takes {TOKEN_EXCHANGE}")
    if one("requested_token_type") != ID_JAG:
        raise Refused("invalid_request", f"AgentGov gives identity assertions: {ID_JAG}")
    kind = one("subject_token_type")
    if kind not in SUBJECT_TOKEN_TYPES:
        raise Refused(
            "invalid_request", f"subject_token_type is one of {', '.join(SUBJECT_TOKEN_TYPES)}"
        )
    audiences = [v for v in fields.get("audience") or [] if v]
    if len(audiences) != 1:
        raise Refused("invalid_target", "name one authorization server, the server's, as audience")
    return Request(
        subject_token=str(one("subject_token")),
        subject_token_type=str(kind),
        audience=audiences[0],
        resource=one("resource", required=False),
        scope=one("scope", required=False),
    )


# --------------------------------------------------------- the token the agent brings


class SubjectTokens:
    """Checks the token an agent brings with Keycloak's keys, fetched again when a token
    names a key AgentGov doesn't know, at most every 30 seconds.

    An access token must be for the gateway, as agents' tokens are; an ID token, for the
    agent's client."""

    def __init__(
        self,
        issuer: str,
        jwks_url: str,
        audience: str,
        *,
        http: httpx.Client | None = None,
    ) -> None:
        self.issuer = issuer
        self.jwks_url = jwks_url
        self.audience = audience
        self._http = http or httpx.Client(timeout=10)
        self._keys: dict[str | None, jwt.PyJWK] = {}
        self._fetched_at = 0.0
        self._lock = threading.Lock()

    def _key(self, token: str) -> jwt.PyJWK:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
            raise Refused("invalid_grant", f"the subject token isn't a JWT: {exc}") from None
        with self._lock:
            stale = time.monotonic() - self._fetched_at > KEYS_REFETCH_SECONDS
            if kid not in self._keys and (stale or not self._keys):
                self._refresh()
            key = self._keys.get(kid)
        if key is None:
            raise Refused("invalid_grant", f"the subject token's key {kid!r} is unknown")
        return key

    def _refresh(self) -> None:
        try:
            resp = self._http.get(self.jwks_url)
            resp.raise_for_status()
            listed = resp.json().get("keys", [])
        except (httpx.HTTPError, ValueError) as exc:
            raise Refused(
                "temporarily_unavailable", f"Keycloak's keys can't be read: {exc}", status=503
            ) from None
        found = {}
        for data in listed:
            if data.get("use", "sig") != "sig":
                continue  # encryption keys
            try:
                found[data.get("kid")] = jwt.PyJWK.from_dict(data)
            except jwt.PyJWTError:
                continue
        self._keys, self._fetched_at = found, time.monotonic()

    def check(self, token: str, kind: str) -> dict[str, Any]:
        """The token's claims, once its signature, issuer and lifetime check out."""
        key = self._key(token)
        access = kind == ACCESS_TOKEN
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key.key,
                algorithms=SUBJECT_ALGORITHMS,
                issuer=self.issuer,
                audience=self.audience if access else None,
                leeway=30,
                options={"require": ["exp", "iat", "iss", "sub"], "verify_aud": access},
            )
        except jwt.PyJWTError as exc:
            raise Refused("invalid_grant", f"the subject token is refused: {exc}") from None
        if not access and not _id_token(claims):
            # Keycloak's other tokens (one exchanged down to a resource server, say) would
            # name an agent and its person to whoever holds them.
            raise Refused(
                "invalid_grant",
                "the subject token isn't an ID token: Keycloak marks those (typ ID), for the "
                "client the person signed in to",
            )
        return claims


def _id_token(claims: Mapping[str, Any]) -> bool:
    """Whether ``claims`` are an ID token's: Keycloak marks it as one, for the one client
    the person signed in to (its audience, and who it was issued to)."""
    audience = claims.get("aud")
    names = [audience] if isinstance(audience, str) else list(audience or [])
    if claims.get("typ") != "ID" or len(names) != 1:
        return False
    return claims.get("azp") in (None, names[0])


def caller(claims: Mapping[str, Any], kind: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """The agent, as the gateway passes an agent's identity (its agent ID and client ID),
    and the person it acts for (None when it acts on its own), from the token's claims."""
    client_id = claims.get("azp")
    if not client_id and kind == ID_TOKEN:
        audience = claims.get("aud")
        names = [audience] if isinstance(audience, str) else list(audience or [])
        client_id = names[0] if len(names) == 1 else None
    identity = {
        k: str(v)
        for k, v in {"agent_id": claims.get("agent_id"), "client_id": client_id}.items()
        if v
    }
    roles = (
        (claims.get("realm_access") or {}).get("roles")
        if isinstance(claims.get("realm_access"), dict)
        else None
    )
    person = people.person_of(
        {
            "subject": claims.get("sub"),
            "username": claims.get("preferred_username"),
            "email": claims.get("email"),
            "groups": claims.get("groups"),
            "roles": roles,
            "act": claims.get("act"),
            "sign_in": claims.get("agentgov_sign_in"),
            "client_id": client_id,
        }
    )
    return identity, person


# ----------------------------------------------------------------------- the ID-JAG


def issue(
    key: ec.EllipticCurvePrivateKey,
    *,
    issuer: str,
    subject: str,
    audience: str,
    client_id: str,
    resource: str,
    actor: str | None = None,
    scope: str | None = None,
    email: str | None = None,
    lifetime: int = MAX_LIFETIME,
    now: int | None = None,
) -> tuple[str, dict[str, Any]]:
    """An ID-JAG, and its claims."""
    issued = int(time.time()) if now is None else now
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "client_id": client_id,
        "jti": uuid.uuid4().hex,
        "iat": issued,
        "exp": issued + max(1, min(lifetime, MAX_LIFETIME)),
        "resource": resource,
    }
    if scope:
        claims["scope"] = scope
    if email:
        claims["email"] = email
    if actor:
        # The agent that acts for the person (RFC 8693's actor claim).
        claims["act"] = {"sub": actor}
    headers = {"typ": TYP, "kid": chains.public_jwk(key.public_key())["kid"]}
    token = jwt.encode(claims, key, algorithm=chains.ALGORITHM, headers=headers)
    return token, claims


def response(token: str, claims: Mapping[str, Any]) -> dict[str, Any]:
    """The token endpoint's answer (RFC 8693 section 2.2.1): an ID-JAG isn't an access
    token, so its token_type is N_A."""
    body: dict[str, Any] = {
        "access_token": token,
        "issued_token_type": ID_JAG,
        "token_type": "N_A",
        "expires_in": int(claims["exp"]) - int(claims["iat"]),
    }
    if claims.get("scope"):
        body["scope"] = claims["scope"]
    return body
