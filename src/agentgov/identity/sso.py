"""Single sign-on for administrators.

The control plane runs the OIDC authorization code flow (with PKCE) as a
confidential client and keeps sessions server-side: the browser is sent to the
identity provider and back to ``/auth/callback``, the control plane redeems the
code and validates the tokens, and the browser only ever holds an HttpOnly
cookie with a random session token (the backend-for-frontend pattern from
OAuth 2.0 for Browser-Based Applications). Provider roles such as
``agentgov-approver`` map to AgentGov roles.

When the provider ends a person's session (they sign out there, from another app, or an
administrator ends it), it can tell the control plane at ``/auth/backchannel-logout``
with a logout token (OpenID Connect Back-Channel Logout 1.0), and their AgentGov sessions
end with it rather than at expiry.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.models import AdminSession, CliLogin, LoginState

# AgentGov roles a person can hold through single sign-on, most privileged first.
SSO_ROLES = ("admin", "approver", "secops", "auditor", "registrar")
# Someone without an AgentGov role, signed in to decide the approval requests sent to
# them (the approvals-by-person feature) or to see the issues sent to them (issues).
PERSON = "person"
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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def pkce_challenge(verifier: str) -> str:
    """The S256 code challenge for a PKCE code verifier (RFC 7636)."""
    return _b64url(hashlib.sha256(verifier.encode()).digest())


def roles_from_claims(claims: dict[str, Any], path: str, prefix: str) -> list[str]:
    """AgentGov roles named in the claim at ``path`` (e.g. ``realm_access.roles``)."""
    value: Any = claims
    for part in path.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    if isinstance(value, str):
        value = value.split()
    if not isinstance(value, list):
        return []
    found = set()
    for item in value:
        if isinstance(item, str):
            name = item.lstrip("/")  # group paths, e.g. "/agentgov-admin"
            if name.startswith(prefix) and name[len(prefix) :] in SSO_ROLES:
                found.add(name[len(prefix) :])
    return [role for role in SSO_ROLES if role in found]


def display_name(claims: dict[str, Any]) -> str:
    """Email when the provider has verified it (sponsor checks compare emails)."""
    if claims.get("email") and claims.get("email_verified") is True:
        return str(claims["email"])
    return str(claims.get("preferred_username") or claims["sub"])


class OIDCClient:
    """The provider side: authorization URLs, code redemption and token validation."""

    def __init__(self, settings: Settings, *, http: httpx.Client | None = None) -> None:
        self.settings = settings
        self.endpoints = settings.oidc_endpoints()
        self._http = http or httpx.Client(timeout=10)
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at = 0.0
        self._lock = threading.Lock()

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
        return f"{self.endpoints['authorization_endpoint']}?{urlencode(query)}"

    def logout_url(self, id_token: str | None) -> str:
        query = {
            "client_id": self.settings.oidc_client_id,
            "post_logout_redirect_uri": self.settings.public_url.rstrip("/") + "/ui/",
        }
        if id_token:
            query["id_token_hint"] = id_token
        return f"{self.endpoints['end_session_endpoint']}?{urlencode(query)}"

    def redeem(self, code: str, code_verifier: str) -> dict[str, Any]:
        try:
            resp = self._http.post(
                self.endpoints["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "code_verifier": code_verifier,
                },
                auth=(self.settings.oidc_client_id, self.settings.oidc_client_secret or ""),
            )
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
        with self._lock:
            if kid not in self._keys and time.monotonic() - self._fetched_at > JWKS_REFETCH_SECONDS:
                self._refresh_keys()
            key = self._keys.get(kid) if kid else next(iter(self._keys.values()), None)
        if key is None:
            raise SSOError("token", f"token signed with unknown key {kid!r}")
        return key

    def _refresh_keys(self) -> None:
        try:
            resp = self._http.get(self.endpoints["jwks_uri"])
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
                issuer=self.endpoints["issuer"],
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
                issuer=self.endpoints["issuer"],
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

    def identify(self, tokens: dict[str, Any], nonce: str) -> Identity:
        """Validate the token response and work out who signed in, with which roles."""
        if "id_token" not in tokens:
            raise SSOError("provider", "token response has no ID token")
        claims = self.validate(
            tokens["id_token"], audience=self.settings.oidc_client_id, nonce=nonce
        )
        path, prefix = self.settings.oidc_roles_claim, self.settings.oidc_role_prefix
        roles = roles_from_claims(claims, path, prefix)
        if not roles and tokens.get("access_token"):
            # Keycloak puts realm roles in the access token, not the ID token.
            access = self.validate(tokens["access_token"], audience=None)
            if access.get("sub") != claims["sub"]:
                raise SSOError("token", "access token belongs to a different subject")
            if access.get("azp") not in (None, self.settings.oidc_client_id):
                raise SSOError("token", "access token was issued to a different client")
            roles = roles_from_claims(access, path, prefix)
        sid = claims.get("sid")
        return Identity(
            subject=str(claims["sub"]),
            name=display_name(claims),
            roles=roles,
            id_token=tokens["id_token"],
            provider_session=sid if isinstance(sid, str) and sid else None,
        )


# --------------------------------------------------------------------- sessions


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
    return login.state, Identity(**login.identity)


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
        },
    )
    return token, record


def record_denied(session: Session, who: Identity) -> None:
    ledger.append(
        session,
        type="admin.login_denied",
        actor=f"sso:{who.name}",
        severity="warning",
        reason="no AgentGov role",
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
