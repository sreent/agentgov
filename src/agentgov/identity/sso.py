"""Single sign-on for administrators.

The control plane runs the OIDC authorization code flow (with PKCE) as a
confidential client and keeps sessions server-side: the browser is sent to the
identity provider and back to ``/auth/callback``, the control plane redeems the
code and validates the tokens, and the browser only ever holds an HttpOnly
cookie with a random session token (the backend-for-frontend pattern from
OAuth 2.0 for Browser-Based Applications). Provider roles such as
``agentgov-approver`` map to AgentGov roles.
"""

from __future__ import annotations

import base64
import hashlib
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
from agentgov.models import AdminSession, LoginState

# AgentGov roles a person can hold through single sign-on, most privileged first.
SSO_ROLES = ("admin", "approver", "auditor", "registrar")
LOGIN_TTL = timedelta(minutes=10)
# Asymmetric algorithms only: a token "signed" with HS256 and the public key must fail.
SIGNING_ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"]
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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


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

    def authorization_url(self, state: str, nonce: str, code_verifier: str) -> str:
        query = {
            "response_type": "code",
            "client_id": self.settings.oidc_client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": _b64url(hashlib.sha256(code_verifier.encode()).digest()),
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
        return Identity(
            subject=str(claims["sub"]),
            name=display_name(claims),
            roles=roles,
            id_token=tokens["id_token"],
        )


# --------------------------------------------------------------------- sessions


def purge_expired(session: Session) -> None:
    now = ids.utcnow()
    session.execute(delete(LoginState).where(LoginState.expires_at < now))
    session.execute(delete(AdminSession).where(AdminSession.expires_at < now))


def begin_login(session: Session, client: OIDCClient) -> tuple[str, str]:
    """Record a new sign-in attempt; returns ``(state, authorization_url)``."""
    purge_expired(session)
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    session.add(
        LoginState(
            state=state, nonce=nonce, code_verifier=verifier, expires_at=ids.utcnow() + LOGIN_TTL
        )
    )
    return state, client.authorization_url(state, nonce, verifier)


def consume_login(session: Session, state: str) -> tuple[str, str]:
    """Take the sign-in attempt for ``state`` (each completes once): ``(nonce, verifier)``."""
    login = session.get(LoginState, state)
    if login is None or login.expires_at < ids.utcnow():
        raise SSOError("expired", "sign-in expired or was already completed")
    session.delete(login)
    return login.nonce, login.code_verifier


def start_session(session: Session, settings: Settings, who: Identity) -> str:
    """Create the session for a signed-in person; returns the cookie token."""
    token = secrets.token_urlsafe(32)
    record = AdminSession(
        id=ids.new_id(ids.SESSION),
        token_hash=token_hash(token),
        subject=who.subject,
        name=who.name,
        roles=who.roles,
        id_token=who.id_token,
        expires_at=ids.utcnow() + timedelta(hours=settings.session_hours),
    )
    session.add(record)
    ledger.append(
        session,
        type="admin.login",
        actor=f"sso:{who.name}",
        details={"roles": who.roles, "subject": who.subject, "session_id": record.id},
    )
    return token


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
