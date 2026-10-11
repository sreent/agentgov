"""Administrator sign-in through the OIDC provider (see agentgov.identity.sso).

The admin UI signs in with a browser session cookie. ``agentgov login`` uses the
same sign-in: it opens ``/auth/login`` with a loopback port and a PKCE challenge,
the browser comes back to the CLI with a one-time code, and the CLI exchanges the
code and its verifier at ``/auth/cli/token`` for a session token of its own.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from agentgov import ids
from agentgov.api.auth import (
    CSRF_HEADER,
    SESSION_COOKIE,
    bearer_token,
    describe,
    session_principal,
)
from agentgov.identity import sso

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["sign-in"])

LOGIN_COOKIE = "agentgov_login"
UI_PATH = "/ui/"
# An S256 PKCE challenge: the unpadded base64url encoding of a SHA-256 digest.
PKCE_CHALLENGE = r"^[A-Za-z0-9_-]{43}$"


def _client(request: Request) -> sso.OIDCClient:
    client = request.app.state.rt.sso
    if client is None:
        raise HTTPException(404, "single sign-on is not configured")
    return client


def _secure(request: Request) -> bool:
    return request.app.state.rt.settings.public_url.startswith("https://")


def _redirect(url: str) -> RedirectResponse:
    resp = RedirectResponse(url, status_code=302)
    resp.delete_cookie(LOGIN_COOKIE, path="/auth")
    return resp


def _back_to_ui(code: str) -> RedirectResponse:
    # Only a fixed code travels in the URL; the UI maps it to its own message.
    return _redirect(f"{UI_PATH}?sso_error={code}")


def _back_to_cli(port: int, **query: str) -> RedirectResponse:
    # The loopback address, never a host from the request: nothing else can receive the code.
    return _redirect(f"http://127.0.0.1:{port}/callback?{urlencode(query)}")


@router.get("/login")
def login(
    request: Request,
    cli_port: int | None = Query(None, ge=1024, le=65535),
    cli_challenge: str | None = Query(None, pattern=PKCE_CHALLENGE),
) -> RedirectResponse:
    """Send the browser to the identity provider.

    ``agentgov login`` adds ``cli_port`` and ``cli_challenge``: the browser then
    goes back to the CLI, listening on that loopback port, rather than the admin UI.
    """
    client = _client(request)
    if (cli_port is None) != (cli_challenge is None):
        raise HTTPException(400, "cli_port and cli_challenge go together")
    with request.app.state.rt.db.session() as s:
        state, url = sso.begin_login(s, client, cli_port=cli_port, cli_challenge=cli_challenge)
    resp = RedirectResponse(url, status_code=302)
    # Binds the callback to this browser. Lax: it must survive the provider's redirect.
    resp.set_cookie(
        LOGIN_COOKIE,
        state,
        max_age=int(sso.LOGIN_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=_secure(request),
        path="/auth",
    )
    return resp


@router.get("/callback")
def callback(
    request: Request,
    state: str | None = None,
    code: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    """The provider's redirect back: redeem the code and start a session."""
    client = _client(request)
    rt = request.app.state.rt
    # Only a sign-in bound to this browser by its login cookie may go back to a CLI.
    bound = bool(state) and request.cookies.get(LOGIN_COOKIE) == state
    port = None
    if bound:
        with rt.db.session() as s:
            port = sso.cli_port(s, state or "")

    def failed(code: str) -> RedirectResponse:
        return _back_to_cli(port, error=code) if port else _back_to_ui(code)

    if error:
        log.info("sign-in failed at the identity provider: %s", error)
        return failed("provider")
    if not bound or not code or not state:
        return failed("state")
    try:
        with rt.db.session() as s:
            nonce, verifier = sso.consume_login(s, state)
        # Network calls happen outside database transactions.
        tokens = client.redeem(code, verifier)
        who = client.identify(tokens, nonce)
    except sso.SSOError as exc:
        log.warning("sign-in failed: %s", exc)
        return failed(exc.code)
    refresh_token = tokens.get("refresh_token") if rt.delegations is not None else None
    with rt.db.session() as s:
        if not who.roles:
            if not sso.people_may_sign_in(s):
                sso.record_denied(s, who)
                return failed("no_role")
            # They see the approval requests and the issues sent to them, and nothing else.
            who = dataclasses.replace(who, roles=[sso.PERSON])
        if port:
            try:
                one_time = sso.cli_signed_in(s, state, who)
            except sso.SSOError as exc:
                return failed(exc.code)
        else:
            token, record = sso.start_session(s, rt.settings, who)
            session_id, expires_at = record.id, record.expires_at
    if port:
        # The CLI collects its session at /auth/cli/token. Until then, the
        # Microsoft sign-in waits under this sign-in's state.
        if refresh_token:
            rt.delegations.remember(state, refresh_token, ids.utcnow() + sso.CLI_CODE_TTL)
        return _back_to_cli(port, code=one_time)
    if refresh_token:
        rt.delegations.remember(session_id, refresh_token, expires_at)
    resp = _redirect(UI_PATH)
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=rt.settings.session_hours * 3600,
        httponly=True,
        samesite="strict",
        secure=_secure(request),
        path="/",
    )
    return resp


@router.get("/session")
def current_session(request: Request) -> dict[str, Any]:
    """Whether this browser is signed in through single sign-on, and as whom.

    Always answers 200 (unlike ``/v1/me``), so the UI can check on first load
    without logging a failed request for every visitor who is not signed in.
    """
    principal = session_principal(request)
    if principal is None:
        return {"signed_in": False}
    return {"signed_in": True, **describe(request.app.state.rt, principal)}


class CliCode(BaseModel):
    code: str = Field(min_length=1, max_length=128)
    verifier: str = Field(min_length=43, max_length=128)


@router.post("/cli/token")
def cli_token(request: Request, body: CliCode) -> dict[str, Any]:
    """Give ``agentgov login`` its session: the one-time code and the PKCE verifier."""
    _client(request)
    rt = request.app.state.rt
    with rt.db.session() as s:
        state, who = sso.collect_cli_login(s, body.code, body.verifier)
    if who is None:
        if state and rt.delegations is not None:
            rt.delegations.forget(state)
        raise HTTPException(
            400, "sign-in expired, was already completed, or was started by another program"
        )
    with rt.db.session() as s:
        token, record = sso.start_session(s, rt.settings, who, client="cli")
        session_id, expires_at = record.id, record.expires_at
    microsoft = False
    if rt.delegations is not None and state:
        rt.delegations.move(state, session_id, expires_at)
        microsoft = rt.delegations.has(session_id)
    return {
        "token": token,
        "expires_at": expires_at.isoformat(),
        "name": who.name,
        "roles": who.roles,
        "microsoft": microsoft,
    }


@router.post("/logout")
def logout(request: Request) -> JSONResponse:
    """End the session; the UI then visits ``logout_url`` to end the provider session.

    The CLI (``agentgov logout``) sends its session token as a bearer token.
    """
    client = _client(request)
    body: dict[str, Any] = {"logout_url": None}
    bearer = bearer_token(request)
    token = bearer or request.cookies.get(SESSION_COOKIE)
    if token:
        if not bearer and request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, "cross-site request refused: send the X-AgentGov-CSRF header")
        rt = request.app.state.rt
        with rt.db.session() as s:
            record = sso.lookup(s, token)
            session_id = record.id if record is not None else None
            id_token = sso.end_session(s, token)
        if session_id and rt.delegations is not None:
            rt.delegations.forget(session_id)
        if id_token is not None:
            body["logout_url"] = client.logout_url(id_token or None)
    resp = JSONResponse(body)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp
