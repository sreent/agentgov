"""Administrator sign-in through the OIDC provider (see agentgov.identity.sso)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from agentgov.api.auth import CSRF_HEADER, SESSION_COOKIE, session_principal
from agentgov.identity import sso

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["sign-in"])

LOGIN_COOKIE = "agentgov_login"
UI_PATH = "/ui/"


def _client(request: Request) -> sso.OIDCClient:
    client = request.app.state.rt.sso
    if client is None:
        raise HTTPException(404, "single sign-on is not configured")
    return client


def _secure(request: Request) -> bool:
    return request.app.state.rt.settings.public_url.startswith("https://")


def _back_to_ui(code: str) -> RedirectResponse:
    # Only a fixed code travels in the URL; the UI maps it to its own message.
    resp = RedirectResponse(f"{UI_PATH}?sso_error={code}", status_code=302)
    resp.delete_cookie(LOGIN_COOKIE, path="/auth")
    return resp


@router.get("/login")
def login(request: Request) -> RedirectResponse:
    """Send the browser to the identity provider."""
    client = _client(request)
    with request.app.state.rt.db.session() as s:
        state, url = sso.begin_login(s, client)
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
    if error:
        log.info("sign-in failed at the identity provider: %s", error)
        return _back_to_ui("provider")
    if not state or not code or request.cookies.get(LOGIN_COOKIE) != state:
        return _back_to_ui("state")
    try:
        with rt.db.session() as s:
            nonce, verifier = sso.consume_login(s, state)
        # Network calls happen outside database transactions.
        who = client.identify(client.redeem(code, verifier), nonce)
    except sso.SSOError as exc:
        log.warning("sign-in failed: %s", exc)
        return _back_to_ui(exc.code)
    with rt.db.session() as s:
        if not who.roles:
            sso.record_denied(s, who)
            return _back_to_ui("no_role")
        token = sso.start_session(s, rt.settings, who)
    resp = RedirectResponse(UI_PATH, status_code=302)
    resp.delete_cookie(LOGIN_COOKIE, path="/auth")
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
    return {"signed_in": True, **principal.describe()}


@router.post("/logout")
def logout(request: Request) -> JSONResponse:
    """End the session; the UI then visits ``logout_url`` to end the provider session."""
    client = _client(request)
    body: dict[str, Any] = {"logout_url": None}
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        if request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, "cross-site request refused: send the X-AgentGov-CSRF header")
        with request.app.state.rt.db.session() as s:
            id_token = sso.end_session(s, token)
        if id_token is not None:
            body["logout_url"] = client.logout_url(id_token or None)
    resp = JSONResponse(body)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp
