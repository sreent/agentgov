"""Single sign-on for administrators.

The control plane runs the OIDC authorization code flow (with PKCE) as a
confidential client and keeps sessions server-side: the browser is sent to the
identity provider and back to ``/auth/callback``, the control plane redeems the
code and validates the tokens, and the browser only ever holds an HttpOnly
cookie with a random session token (the backend-for-frontend pattern from
OAuth 2.0 for Browser-Based Applications). Provider roles such as
``agentgov-approver`` map to AgentGov roles.

Any OpenID Connect provider can sign people in: Keycloak's and Microsoft Entra ID's
endpoints are known, and other providers' are read from their discovery document
(OpenID Connect Discovery 1.0). Roles come from a claim of the provider's tokens (group
names with the ``agentgov-`` prefix, or values mapped to roles), and from the roles given
to people in AgentGov itself (agentgov.registry.access).

When the provider ends a person's session (they sign out there, from another app, or an
administrator ends it), it can tell the control plane at ``/auth/backchannel-logout``
with a logout token (OpenID Connect Back-Channel Logout 1.0), and their AgentGov sessions
end with it rather than at expiry.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.models import AdminSession, CliLogin, LoginState, RoleGrant

log = logging.getLogger(__name__)

# AgentGov roles a person can hold through single sign-on, most privileged first.
SSO_ROLES = ("admin", "approver", "secops", "auditor", "registrar")
# Someone without an AgentGov role, signed in to decide the approval requests sent to
# them (the approvals-by-person feature) or to see the issues sent to them (issues).
PERSON = "person"
# The roles the provider (agentgov-person, ...) or AgentGov can give. The person role, given,
# lets someone in even when only people with a role may sign in (AGENTGOV_OIDC_REQUIRE_ROLE).
GIVABLE = (*SSO_ROLES, PERSON)
# Each of these can be held for one team's agents only: "approver@sales" is the approver role
# for team sales' agents (docs/administration.md#roles-for-one-team).
TEAM_ROLES = SSO_ROLES
# The features that let them sign in: while one is on.
PERSON_FEATURES = ("approvals-by-person", "issues")
LOGIN_TTL = timedelta(minutes=10)
# How long the CLI has to collect its session once the person has signed in.
CLI_CODE_TTL = timedelta(minutes=2)
# Asymmetric algorithms only: a token "signed" with HS256 and the public key must fail.
SIGNING_ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"]
# What makes a token a logout token (OpenID Connect Back-Channel Logout 1.0).
LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
JWKS_REFETCH_SECONDS = 30
# Where a provider publishes its endpoints (OpenID Connect Discovery 1.0), under its issuer,
# and how long AgentGov uses what it read there before reading it again.
DISCOVERY_PATH = "/.well-known/openid-configuration"
DISCOVERY_SECONDS = 3600
# While the provider can't be read, how long the last document read is used before trying
# again (rather than at every step of every sign-in).
DISCOVERY_RETRY_SECONDS = 60
ENDPOINTS = ("authorization_endpoint", "token_endpoint", "jwks_uri", "end_session_endpoint")
# The endpoints sign-in can't do without (a provider without a logout endpoint only signs
# people out of AgentGov).
REQUIRED_ENDPOINTS = ENDPOINTS[:3]


class SSOError(Exception):
    """A sign-in failed. ``code`` is shown to the user as a fixed message."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True)
class Identity:
    subject: str
    name: str
    roles: list[str]
    id_token: str
    # The provider's session (the ID token's sid), which its logout tokens name.
    provider_session: str | None = None
    # Their email address, where the provider vouches for it (verified_email): the roles
    # given in AgentGov are given to it.
    email: str | None = None
    # The roles of theirs given in AgentGov rather than by the provider.
    given: tuple[str, ...] = ()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def pkce_challenge(verifier: str) -> str:
    """The S256 code challenge for a PKCE code verifier (RFC 7636)."""
    return _b64url(hashlib.sha256(verifier.encode()).digest())


def claim_values(claims: dict[str, Any], path: str) -> list[str]:
    """The strings in the claim at ``path``: the claim of that name (namespaced claims, such
    as ``https://example.com/roles``, have dots in their names), or else a dot path into
    nested claims (``realm_access.roles``). A string is taken whole and word by word."""
    value: Any = claims.get(path)
    if value is None:
        value = claims
        for part in path.split("."):
            value = value.get(part) if isinstance(value, dict) else None
    if isinstance(value, str):
        return list(dict.fromkeys([value, *value.split()]))
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def split_role(value: str) -> tuple[str, str | None]:
    """A role and the team it is held for: ("approver", "sales") for "approver@sales", and
    no team for a role held for every team."""
    role, mark, team = value.partition("@")
    return (role, team) if mark and team else (value, None)


def for_team(role: str, team: str) -> str:
    return f"{role}@{team}"


def is_team_role(value: str) -> bool:
    role, team = split_role(value)
    return team is not None and role in TEAM_ROLES


def known_role(value: str) -> bool:
    """A role the provider or AgentGov can give: for every team, or for one."""
    return value in GIVABLE or is_team_role(value)


def ordered(roles: Any) -> list[str]:
    """The known ones of ``roles``, most privileged first: those for every team (the person
    role last), then those for one team, by role and team."""
    given = set(roles)
    every = [role for role in GIVABLE if role in given]
    one = sorted(
        (r for r in given if is_team_role(r)),
        key=lambda r: (TEAM_ROLES.index(split_role(r)[0]), str(split_role(r)[1]).lower()),
    )
    return every + one


def roles_from_claims(
    claims: dict[str, Any],
    paths: str | Sequence[str],
    prefix: str,
    role_map: dict[str, set[str]] | None = None,
) -> list[str]:
    """AgentGov roles named in the claims at ``paths`` (e.g. ``realm_access.roles``): the
    values ``role_map`` maps to roles when there is one, else the names with ``prefix``
    (``agentgov-approver`` is the approver role, ``agentgov-approver@sales`` the approver
    role for team sales)."""
    found: set[str] = set()
    for path in [paths] if isinstance(paths, str) else paths:
        for item in claim_values(claims, path):
            if role_map:
                found |= role_map.get(item, set())
                continue
            name = item.lstrip("/")  # group paths, e.g. "/agentgov-admin"
            if name.startswith(prefix) and known_role(name[len(prefix) :]):
                found.add(name[len(prefix) :])
    return ordered(found)


def _true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() in ("true", "1"))


def verified_email(claims: dict[str, Any], provider: str = "oidc") -> str | None:
    """The person's email address, where the provider vouches for it: one it verified
    (email_verified). Microsoft Entra ID verifies none, but only the tenant's
    administrators set a person's email address and user principal name: its email,
    unless the tenant says the address's domain isn't one it verified (xms_edov), or
    else the user principal name."""
    email = claims.get("email")
    if isinstance(email, str) and "@" in email:
        if _true(claims.get("email_verified")):
            return email
        if provider == "entra" and not ("xms_edov" in claims and not _true(claims.get("xms_edov"))):
            return email
    upn = claims.get("preferred_username")
    if provider == "entra" and isinstance(upn, str) and "@" in upn:
        return upn
    return None


def display_name(claims: dict[str, Any], provider: str = "oidc") -> str:
    """Email when the provider vouches for it (sponsor checks compare emails)."""
    return verified_email(claims, provider) or str(
        claims.get("preferred_username") or claims["sub"]
    )


def _absolute(url: Any) -> bool:
    return (
        isinstance(url, str)
        and urlsplit(url).scheme in ("https", "http")
        and bool(urlsplit(url).netloc)
    )


class OIDCClient:
    """The provider side: its endpoints, authorization URLs, code redemption and token
    validation."""

    def __init__(self, settings: Settings, *, http: httpx.Client | None = None) -> None:
        self.settings = settings
        self.provider = settings.oidc_provider
        self.roles_claims = settings.oidc_roles_claims()
        self.role_map = settings.oidc_role_pairs()
        self.domains = settings.oidc_domains()
        self._configured = settings.oidc_endpoints()
        self._http = http or httpx.Client(timeout=10)
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at = 0.0
        self._lock = threading.Lock()
        self._metadata: dict[str, Any] | None = None
        self._metadata_at = 0.0
        self._metadata_lock = threading.Lock()

    @property
    def discovers(self) -> bool:
        """Whether the provider's endpoints come from its discovery document: for providers
        other than Keycloak and Microsoft Entra ID whose endpoints aren't all set."""
        return any(not self._configured.get(name) for name in REQUIRED_ENDPOINTS)

    def metadata(self) -> dict[str, Any]:
        """The provider's discovery document, read when first needed and again after an
        hour. While the provider can't be reached, the last one read is used."""
        with self._metadata_lock:
            if (
                self._metadata is not None
                and time.monotonic() - self._metadata_at < DISCOVERY_SECONDS
            ):
                return self._metadata
            try:
                document = self._discover()
            except SSOError as exc:
                if self._metadata is None:
                    raise
                log.warning("using the identity provider's last discovery document: %s", exc)
                self._metadata_at = time.monotonic() - DISCOVERY_SECONDS + DISCOVERY_RETRY_SECONDS
                return self._metadata
            self._metadata, self._metadata_at = document, time.monotonic()
            return document

    def _discover(self) -> dict[str, Any]:
        configured = str(self._configured.get("issuer") or "")
        url = configured.rstrip("/") + DISCOVERY_PATH
        try:
            resp = self._http.get(url)
            resp.raise_for_status()
            document = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise SSOError(
                "provider", f"cannot read the identity provider's discovery document {url}: {exc}"
            ) from exc
        if not isinstance(document, dict):
            raise SSOError("provider", f"{url} is not a discovery document")
        # The document must be the issuer's own (OpenID Connect Discovery 1.0, 4.3), give or
        # take a trailing slash, which some providers' issuers end in (Auth0's) and their
        # administrators often leave off.
        issuer = document.get("issuer")
        if not isinstance(issuer, str) or issuer.rstrip("/") != configured.rstrip("/"):
            raise SSOError(
                "provider",
                f"the discovery document {url} is for issuer {issuer!r}, not {configured!r}",
            )
        for name in REQUIRED_ENDPOINTS:
            if not self._configured.get(name) and not _absolute(document.get(name)):
                raise SSOError("provider", f"the discovery document {url} names no {name}")
        return document

    @property
    def endpoints(self) -> dict[str, Any]:
        """The issuer and the endpoints: those set or known, the rest discovered. Raises
        SSOError when they must be discovered and the provider can't be read."""
        if not self.discovers:
            return self._configured
        document = self.metadata()
        found = {
            name: document[name] if _absolute(document.get(name)) else None for name in ENDPOINTS
        }
        mine = {name: value for name, value in self._configured.items() if value}
        return {**found, **mine, "issuer": document["issuer"]}

    def prepare(self) -> None:
        """Read the provider's discovery document now if it is needed, so that the
        sign-in's database transaction makes no network call."""
        self.endpoints  # noqa: B018

    @property
    def issuers(self) -> list[str]:
        """The issuer tokens must name: as set or discovered, with or without a trailing
        slash."""
        issuer = str(self.endpoints["issuer"])
        return list(dict.fromkeys([issuer, issuer.rstrip("/"), issuer.rstrip("/") + "/"]))

    @property
    def client_auth(self) -> str:
        """How AgentGov shows its secret at the token endpoint: basic unless set, or the
        provider takes only client_secret_post."""
        if self.settings.oidc_client_auth:
            return self.settings.oidc_client_auth
        if self.discovers:
            supported = self.metadata().get("token_endpoint_auth_methods_supported")
            if (
                isinstance(supported, list)
                and "client_secret_basic" not in supported
                and "client_secret_post" in supported
            ):
                return "client_secret_post"
        return "client_secret_basic"

    @property
    def redirect_uri(self) -> str:
        return self.settings.public_url.rstrip("/") + "/auth/callback"

    @property
    def scopes(self) -> str:
        scopes = self.settings.oidc_scopes.split()
        if self.settings.microsoft_admin_actions and "offline_access" not in scopes:
            scopes.append("offline_access")  # a refresh token, to act as the admin
        return " ".join(scopes)

    def authorization_url(self, state: str, nonce: str, code_verifier: str) -> str:
        query = {
            "response_type": "code",
            "client_id": self.settings.oidc_client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce_challenge(code_verifier),
            "code_challenge_method": "S256",
        }
        endpoint = self.endpoints["authorization_endpoint"]
        return f"{endpoint}{'&' if '?' in endpoint else '?'}{urlencode(query)}"

    def logout_url(self, id_token: str | None) -> str | None:
        """Where the browser goes to end the provider's session too, if the provider has a
        logout endpoint (Google and Dex, for instance, don't)."""
        try:
            endpoint = self.endpoints.get("end_session_endpoint")
        except SSOError:
            return None
        if not endpoint:
            return None
        query = {
            "client_id": self.settings.oidc_client_id,
            "post_logout_redirect_uri": self.settings.public_url.rstrip("/") + "/ui/",
        }
        if id_token:
            query["id_token_hint"] = id_token
        return f"{endpoint}{'&' if '?' in endpoint else '?'}{urlencode(query)}"

    def redeem(self, code: str, code_verifier: str) -> dict[str, Any]:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": code_verifier,
        }
        client_id, secret = self.settings.oidc_client_id, self.settings.oidc_client_secret or ""
        auth = None
        if self.client_auth == "client_secret_post":
            data |= {"client_id": client_id, "client_secret": secret}
        else:
            auth = (client_id, secret)
        try:
            resp = self._http.post(self.endpoints["token_endpoint"], data=data, auth=auth)
        except httpx.HTTPError as exc:
            raise SSOError("provider", f"identity provider unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise SSOError("provider", f"token endpoint answered {resp.status_code}: {resp.text}")
        return resp.json()

    def _key_for(self, token: str) -> jwt.PyJWK:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
            raise SSOError("token", f"malformed token: {exc}") from exc
        jwks_uri = self.endpoints["jwks_uri"]
        with self._lock:
            if kid not in self._keys and time.monotonic() - self._fetched_at > JWKS_REFETCH_SECONDS:
                self._refresh_keys(jwks_uri)
            key = self._keys.get(kid) if kid else next(iter(self._keys.values()), None)
        if key is None:
            raise SSOError("token", f"token signed with unknown key {kid!r}")
        return key

    def _refresh_keys(self, jwks_uri: str) -> None:
        try:
            resp = self._http.get(jwks_uri)
            resp.raise_for_status()
            jwks = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise SSOError("provider", f"cannot fetch signing keys: {exc}") from exc
        keys = {}
        for data in jwks.get("keys", []):
            if data.get("use", "sig") != "sig":
                continue  # encryption keys
            try:
                keys[data.get("kid")] = jwt.PyJWK.from_dict(data)
            except jwt.PyJWTError:
                continue  # key types or algorithms this library cannot use
        self._keys = keys
        self._fetched_at = time.monotonic()

    def validate(
        self, token: str, *, audience: str | None, nonce: str | None = None
    ) -> dict[str, Any]:
        key = self._key_for(token)
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=[key.algorithm_name]
                if key.algorithm_name in SIGNING_ALGORITHMS
                else SIGNING_ALGORITHMS,
                audience=audience,
                issuer=self.issuers,
                leeway=30,
                options={
                    "require": ["exp", "iat", "iss", "sub"],
                    "verify_aud": audience is not None,
                },
            )
        except jwt.PyJWTError as exc:
            raise SSOError("token", f"token rejected: {exc}") from exc
        if nonce is not None and claims.get("nonce") != nonce:
            raise SSOError("state", "ID token nonce does not match this sign-in")
        return claims

    def validate_logout(self, token: str) -> dict[str, Any]:
        """A logout token: the provider's signature, for this client, with the logout
        event, naming a session (sid) or a person (sub), and no nonce, which would make it
        an ID token (OpenID Connect Back-Channel Logout 1.0, 2.6)."""
        key = self._key_for(token)
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=[key.algorithm_name]
                if key.algorithm_name in SIGNING_ALGORITHMS
                else SIGNING_ALGORITHMS,
                audience=self.settings.oidc_client_id,
                issuer=self.issuers,
                leeway=30,
                options={"require": ["iat", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise SSOError("token", f"logout token rejected: {exc}") from exc
        events = claims.get("events")
        if not isinstance(events, dict) or not isinstance(events.get(LOGOUT_EVENT), dict):
            raise SSOError("token", "not a logout token: it has no back-channel logout event")
        if not isinstance(claims.get("sid"), str) and not isinstance(claims.get("sub"), str):
            raise SSOError("token", "the logout token names no session (sid) or person (sub)")
        if "nonce" in claims:
            raise SSOError("token", "a logout token has no nonce")
        return claims

    def allowed(self, claims: dict[str, Any], email: str | None) -> bool:
        """Whether the person's organisation may sign in (AGENTGOV_OIDC_ALLOWED_DOMAINS):
        their verified email address's domain, and with Google, a Google Workspace or Cloud
        Identity account (its hosted domain, hd), not a personal one."""
        if not self.domains:
            return True
        domain = email.rsplit("@", 1)[1].lower() if email else None
        if self.provider == "google":
            hosted = claims.get("hd")
            if not isinstance(hosted, str) or not hosted:
                return False
            return hosted.lower() in self.domains or domain in self.domains
        return domain in self.domains

    def roles(self, claims: dict[str, Any]) -> list[str]:
        prefix = self.settings.oidc_role_prefix
        return roles_from_claims(claims, self.roles_claims, prefix, self.role_map)

    def identify(self, tokens: dict[str, Any], nonce: str) -> Identity:
        """Validate the token response and work out who signed in, with which roles."""
        if "id_token" not in tokens:
            raise SSOError("provider", "token response has no ID token")
        claims = self.validate(
            tokens["id_token"], audience=self.settings.oidc_client_id, nonce=nonce
        )
        email = verified_email(claims, self.provider)
        if not self.allowed(claims, email):
            raise SSOError(
                "domain", f"{email or claims['sub']} is not in a domain allowed to sign in"
            )
        roles = self.roles(claims)
        if not roles and self.provider == "keycloak" and tokens.get("access_token"):
            # Keycloak puts realm roles in the access token, not the ID token. Other
            # providers' access tokens are for other APIs (Microsoft Graph's), or name the
            # person differently (Okta's subject is their login): roles come from their
            # ID tokens.
            roles = self._access_token_roles(tokens["access_token"], str(claims["sub"]))
        sid = claims.get("sid")
        return Identity(
            subject=str(claims["sub"]),
            name=display_name(claims, self.provider),
            roles=roles,
            id_token=tokens["id_token"],
            provider_session=sid if isinstance(sid, str) and sid else None,
            email=email,
        )

    def _access_token_roles(self, token: str, subject: str) -> list[str]:
        """Roles from Keycloak's access token, which must be about the same person, for
        AgentGov's client."""
        access = self.validate(token, audience=None)
        if access.get("sub") != subject:
            raise SSOError("token", "access token belongs to a different subject")
        if access.get("azp") not in (None, self.settings.oidc_client_id):
            raise SSOError("token", "access token was issued to a different client")
        return self.roles(access)


# --------------------------------------------------------------------- sessions


def with_given_roles(session: Session, who: Identity) -> Identity:
    """Add the roles given to the person in AgentGov (agentgov.registry.access), by the
    email address the provider vouches for."""
    if not who.email:
        return who
    given = set(session.scalars(select(RoleGrant.role).where(RoleGrant.email == who.email.lower())))
    if not given:
        return who
    return replace(who, roles=ordered(given | set(who.roles)), given=tuple(ordered(given)))


def without_role(session: Session, settings: Settings) -> str | None:
    """What someone gets who signs in with no role given to them: the person role, to see
    what is sent to them, while issues or approvals go to people; None if they are refused
    then (AGENTGOV_OIDC_REQUIRE_ROLE)."""
    if settings.oidc_require_role or not people_may_sign_in(session):
        return None
    return PERSON


def admit(session: Session, settings: Settings, who: Identity) -> Identity | None:
    """Who signed in, with the roles they sign in with, or None if they may not sign in.

    Their AgentGov roles, if they have one, for every team or for one. Otherwise the person
    role, while issues or approvals go to people: given to them, by the provider or in
    AgentGov, or else to anyone the provider signs in, unless only people with a role may sign
    in. Given, it is stored as their role; unasked, their session has none, so that requiring
    a role ends it too."""
    held = [role for role in ordered(who.roles) if role != PERSON]
    if held:
        return replace(who, roles=held)
    if not people_may_sign_in(session):
        return None
    if PERSON in who.roles:
        return replace(who, roles=[PERSON])
    if without_role(session, settings) is None:
        return None
    return replace(who, roles=[])


def people_may_sign_in(session: Session) -> bool:
    """Whether people without an AgentGov role may sign in, to see what was sent to them."""
    from agentgov.registry import features

    return any(features.is_on(session, name) for name in PERSON_FEATURES)


def purge_expired(session: Session) -> None:
    now = ids.utcnow()
    session.execute(delete(LoginState).where(LoginState.expires_at < now))
    session.execute(delete(CliLogin).where(CliLogin.expires_at < now))
    session.execute(delete(AdminSession).where(AdminSession.expires_at < now))


def begin_login(
    session: Session,
    client: OIDCClient,
    *,
    cli_port: int | None = None,
    cli_challenge: str | None = None,
) -> tuple[str, str]:
    """Record a new sign-in attempt; returns ``(state, authorization_url)``.

    ``cli_port`` and ``cli_challenge`` mark a sign-in for ``agentgov login``: the
    browser goes back to the CLI on that loopback port, and the CLI must present
    the verifier for that PKCE challenge to collect its session.
    """
    purge_expired(session)
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    expires_at = ids.utcnow() + LOGIN_TTL
    session.add(LoginState(state=state, nonce=nonce, code_verifier=verifier, expires_at=expires_at))
    if cli_port is not None and cli_challenge is not None:
        session.add(
            CliLogin(state=state, port=cli_port, challenge=cli_challenge, expires_at=expires_at)
        )
    return state, client.authorization_url(state, nonce, verifier)


def consume_login(session: Session, state: str) -> tuple[str, str]:
    """Take the sign-in attempt for ``state`` (each completes once): ``(nonce, verifier)``."""
    login = session.get(LoginState, state)
    if login is None or login.expires_at < ids.utcnow():
        raise SSOError("expired", "sign-in expired or was already completed")
    session.delete(login)
    return login.nonce, login.code_verifier


def cli_port(session: Session, state: str) -> int | None:
    """The CLI's loopback port, if ``agentgov login`` started this sign-in."""
    login = session.get(CliLogin, state)
    return login.port if login is not None else None


def cli_signed_in(session: Session, state: str, who: Identity) -> str:
    """The person signed in for the CLI: keep who they are; returns the one-time code."""
    login = session.get(CliLogin, state)
    if login is None:
        raise SSOError("expired", "sign-in expired or was already completed")
    code = secrets.token_urlsafe(32)
    login.code_hash = token_hash(code)
    login.identity = {
        "subject": who.subject,
        "name": who.name,
        "roles": who.roles,
        "id_token": who.id_token,
        "provider_session": who.provider_session,
        "email": who.email,
        "given": list(who.given),
    }
    login.expires_at = ids.utcnow() + CLI_CODE_TTL
    return code


def collect_cli_login(
    session: Session, code: str, verifier: str
) -> tuple[str | None, Identity | None]:
    """Who signed in for a one-time code, if ``verifier`` matches its PKCE challenge.

    Returns the sign-in's state (``None`` for an unknown code) and who signed in
    (``None`` unless the code is current and the verifier right). Each code works
    once: it is used up even when the verifier is wrong.
    """
    login = session.scalar(select(CliLogin).where(CliLogin.code_hash == token_hash(code)))
    if login is None:
        return None, None
    session.delete(login)
    if login.identity is None or login.expires_at < ids.utcnow():
        return login.state, None
    if not hmac.compare_digest(pkce_challenge(verifier), login.challenge):
        return login.state, None
    identity = dict(login.identity)
    identity["given"] = tuple(identity.get("given") or ())
    return login.state, Identity(**identity)


def start_session(
    session: Session, settings: Settings, who: Identity, *, client: str = "browser"
) -> tuple[str, AdminSession]:
    """Create the session for a signed-in person; returns its token and record."""
    token = secrets.token_urlsafe(32)
    record = AdminSession(
        id=ids.new_id(ids.SESSION),
        token_hash=token_hash(token),
        subject=who.subject,
        name=who.name,
        email=who.email,
        roles=who.roles,
        id_token=who.id_token,
        provider_session=who.provider_session,
        expires_at=ids.utcnow() + timedelta(hours=settings.session_hours),
    )
    session.add(record)
    ledger.append(
        session,
        type="admin.login",
        actor=f"sso:{who.name}",
        details={
            "roles": who.roles,
            "subject": who.subject,
            "session_id": record.id,
            "client": client,
            **({"given_in_agentgov": list(who.given)} if who.given else {}),
        },
    )
    return token, record


def record_denied(session: Session, who: Identity, *, reason: str = "no AgentGov role") -> None:
    ledger.append(
        session,
        type="admin.login_denied",
        actor=f"sso:{who.name}",
        severity="warning",
        reason=reason,
        details={"subject": who.subject},
    )


def lookup(session: Session, token: str) -> AdminSession | None:
    record = session.scalar(
        select(AdminSession).where(AdminSession.token_hash == token_hash(token))
    )
    if record is None or record.expires_at <= ids.utcnow():
        return None
    return record


def end_session(session: Session, token: str) -> str | None:
    """Sign out; returns the ID token for the provider logout, if the session existed."""
    record = lookup(session, token)
    if record is None:
        return None
    id_token = record.id_token
    ledger.append(
        session,
        type="admin.logout",
        actor=f"sso:{record.name}",
        details={"session_id": record.id},
    )
    session.delete(record)
    return id_token or ""


def end_provider_sessions(session: Session, claims: dict[str, Any]) -> list[str]:
    """End the sessions a logout token names: those from its provider session (sid), or,
    when it names only a person (sub), all of theirs. Returns the IDs of those ended."""
    sid, sub = claims.get("sid"), claims.get("sub")
    query = select(AdminSession)
    if isinstance(sid, str):
        query = query.where(AdminSession.provider_session == sid)
        if isinstance(sub, str):
            query = query.where(AdminSession.subject == sub)
    else:
        query = query.where(AdminSession.subject == sub)
    ended = []
    for record in session.scalars(query.order_by(AdminSession.id)):
        ledger.append(
            session,
            type="admin.logout",
            actor=f"sso:{record.name}",
            reason="the identity provider ended the session",
            details={"session_id": record.id, "by": "identity provider"},
        )
        session.delete(record)
        ended.append(record.id)
    return ended
