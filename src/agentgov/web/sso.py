"""Administrator sign-in through the OIDC provider (see agentgov.identity.sso).

The admin UI signs in with a browser session cookie. ``agentgov login`` uses the
same sign-in: it opens ``/auth/login`` with a loopback port and a PKCE challenge,
the browser comes back to the CLI with a one-time code, and the CLI exchanges the
code and its verifier at ``/auth/cli/token`` for a session token of its own.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlencode

from django.http import HttpRequest, HttpResponse
from ninja import Body, Query
from pydantic import BaseModel, Field

from agentgov import ids
from agentgov.api.auth import (
    CSRF_HEADER,
    SESSION_COOKIE,
    bearer_token,
    describe,
)
from agentgov.identity import sso
from agentgov.web.api import (
    HTTPException,
    Router,
    delete_cookie,
    json_response,
    raw_response,
    redirect_response,
    set_cookie,
)
from agentgov.web.auth import runtime, session_principal

log = logging.getLogger(__name__)
router = Router(tags=["sign-in"])

LOGIN_COOKIE = "agentgov_login"
# Where in the UI to go once signed in: a page of the UI (its hash), such as an issue an
# email links to, and nothing else, so that it can't send anyone off the control plane.
NEXT_COOKIE = "agentgov_next"
NEXT_PAGE = r"^#/[A-Za-z0-9_\-/?=&.%]*$"
UI_PATH = "/ui/"
# An S256 PKCE challenge: the unpadded base64url encoding of a SHA-256 digest.
PKCE_CHALLENGE = r"^[A-Za-z0-9_-]{43}$"


def _client(request: HttpRequest) -> sso.OIDCClient:
    client = runtime(request).sso
    if client is None:
        raise HTTPException(404, "single sign-on is not configured")
    return client


def _secure(request: HttpRequest) -> bool:
    return runtime(request).settings.public_url.startswith("https://")


def _redirect(url: str) -> HttpResponse:
    resp = redirect_response(url, status_code=302)
    delete_cookie(resp, LOGIN_COOKIE, path="/auth")
    delete_cookie(resp, NEXT_COOKIE, path="/auth")
    return resp


def _back_to_ui(code: str) -> HttpResponse:
    # Only a fixed code travels in the URL; the UI maps it to its own message.
    return _redirect(f"{UI_PATH}?sso_error={code}")


def _back_to_cli(port: int, **query: str) -> HttpResponse:
    # The loopback address, never a host from the request: nothing else can receive the code.
    return _redirect(f"http://127.0.0.1:{port}/callback?{urlencode(query)}")


@router.get("/auth/login")
def login(
    request: HttpRequest,
    cli_port: int | None = Query(None, ge=1024, le=65535),
    cli_challenge: str | None = Query(None, pattern=PKCE_CHALLENGE),
    next: str | None = Query(None, pattern=NEXT_PAGE, max_length=500),
) -> HttpResponse:
    """Send the browser to the identity provider.

    ``agentgov login`` adds ``cli_port`` and ``cli_challenge``: the browser then
    goes back to the CLI, listening on that loopback port, rather than the admin UI.
    """
    client = _client(request)
    if (cli_port is None) != (cli_challenge is None):
        raise HTTPException(400, "cli_port and cli_challenge go together")
    try:
        client.prepare()  # the provider's endpoints, read before the transaction
    except sso.SSOError as exc:
        log.warning("cannot sign in: %s", exc)
        return _back_to_cli(cli_port, error=exc.code) if cli_port else _back_to_ui(exc.code)
    with runtime(request).db.transaction() as tx:
        state, url = sso.begin_login(tx, client, cli_port=cli_port, cli_challenge=cli_challenge)
    resp = redirect_response(url, status_code=302)
    # Binds the callback to this browser. Lax: it must survive the provider's redirect.
    set_cookie(
        resp,
        LOGIN_COOKIE,
        state,
        max_age=int(sso.LOGIN_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=_secure(request),
        path="/auth",
    )
    if next and cli_port is None:
        set_cookie(
            resp,
            NEXT_COOKIE,
            next,
            max_age=int(sso.LOGIN_TTL.total_seconds()),
            httponly=True,
            samesite="lax",
            secure=_secure(request),
            path="/auth",
        )
    return resp


@router.get("/auth/callback")
def callback(
    request: HttpRequest,
    state: str | None = None,
    code: str | None = None,
    error: str | None = None,
) -> HttpResponse:
    """The provider's redirect back: redeem the code and start a session."""
    client = _client(request)
    rt = runtime(request)
    # Only a sign-in bound to this browser by its login cookie may go back to a CLI.
    bound = bool(state) and request.COOKIES.get(LOGIN_COOKIE) == state
    port = None
    if bound:
        with rt.db.transaction() as tx:
            port = sso.cli_port(tx, state or "")

    def failed(code: str) -> HttpResponse:
        return _back_to_cli(port, error=code) if port else _back_to_ui(code)

    if error:
        log.info("sign-in failed at the identity provider: %s", error)
        return failed("provider")
    if not bound or not code or not state:
        return failed("state")
    try:
        with rt.db.transaction() as tx:
            nonce, verifier = sso.consume_login(tx, state)
        # Network calls happen outside database transactions.
        tokens = client.redeem(code, verifier)
        who = client.identify(tokens, nonce)
    except sso.SSOError as exc:
        log.warning("sign-in failed: %s", exc)
        return failed(exc.code)
    refresh_token = tokens.get("refresh_token") if rt.delegations is not None else None
    with rt.db.transaction() as tx:
        admitted = sso.admit(tx, rt.settings, sso.with_given_roles(tx, who))
        if admitted is None:
            sso.record_denied(tx, who)
            return failed("no_role")
        # Without an AgentGov role, they see the approval requests and the issues sent to
        # them, and nothing else.
        who = admitted
        if port:
            try:
                one_time = sso.cli_signed_in(tx, state, who)
            except sso.SSOError as exc:
                return failed(exc.code)
        else:
            token, record = sso.start_session(tx, rt.settings, who)
            session_id, expires_at = record.id, record.expires_at
    if port:
        # The CLI collects its session at /auth/cli/token. Until then, the
        # Microsoft sign-in waits under this sign-in's state.
        if refresh_token:
            rt.delegations.remember(state, refresh_token, ids.utcnow() + sso.CLI_CODE_TTL)
        return _back_to_cli(port, code=one_time)
    if refresh_token:
        rt.delegations.remember(session_id, refresh_token, expires_at)
    page = request.COOKIES.get(NEXT_COOKIE) or ""
    resp = _redirect(UI_PATH + (page if re.match(NEXT_PAGE, page) else ""))
    set_cookie(
        resp,
        SESSION_COOKIE,
        token,
        max_age=rt.settings.session_hours * 3600,
        httponly=True,
        samesite="strict",
        secure=_secure(request),
        path="/",
    )
    return resp


@router.get("/auth/session")
def current_session(request: HttpRequest) -> dict[str, Any]:
    """Whether this browser is signed in through single sign-on, and as whom.

    Always answers 200 (unlike ``/v1/me``), so the UI can check on first load
    without logging a failed request for every visitor who is not signed in.
    """
    principal = session_principal(request)
    if principal is None:
        return {"signed_in": False}
    return {"signed_in": True, **describe(runtime(request), principal)}


class CliCode(BaseModel):
    code: str = Field(min_length=1, max_length=128)
    verifier: str = Field(min_length=43, max_length=128)


@router.post("/auth/cli/token")
def cli_token(request: HttpRequest, body: CliCode = Body(...)) -> dict[str, Any]:
    """Give ``agentgov login`` its session: the one-time code and the PKCE verifier."""
    _client(request)
    rt = runtime(request)
    with rt.db.transaction() as tx:
        state, who = sso.collect_cli_login(tx, body.code, body.verifier)
    if who is None:
        if state and rt.delegations is not None:
            rt.delegations.forget(state)
        raise HTTPException(
            400, "sign-in expired, was already completed, or was started by another program"
        )
    with rt.db.transaction() as tx:
        token, record = sso.start_session(tx, rt.settings, who, client="cli")
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


@router.post("/auth/logout")
def logout(request: HttpRequest) -> HttpResponse:
    """End the session; the UI then visits ``logout_url`` to end the provider session.

    The CLI (``agentgov logout``) sends its session token as a bearer token.
    """
    client = _client(request)
    body: dict[str, Any] = {"logout_url": None}
    bearer = bearer_token(request)
    token = bearer or request.COOKIES.get(SESSION_COOKIE)
    if token:
        if not bearer and request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, "cross-site request refused: send the X-AgentGov-CSRF header")
        rt = runtime(request)
        with rt.db.transaction() as tx:
            record = sso.lookup(tx, token)
            session_id = record.id if record is not None else None
            id_token = sso.end_session(tx, token)
        if session_id and rt.delegations is not None:
            rt.delegations.forget(session_id)
        if id_token is not None:
            body["logout_url"] = client.logout_url(id_token or None)
    resp = json_response(body)
    delete_cookie(resp, SESSION_COOKIE, path="/")
    return resp


@router.post("/auth/backchannel-logout")
def backchannel_logout(request: HttpRequest) -> HttpResponse:
    """The identity provider ended a person's session: end the AgentGov sessions that came
    from it (OpenID Connect Back-Channel Logout 1.0). The provider posts a logout token it
    signed for AgentGov's client, which names the session or the person."""
    client = _client(request)
    try:
        fields = parse_qs(request.body.decode())
    except UnicodeDecodeError:
        fields = {}
    tokens = fields.get("logout_token") or []
    if len(tokens) != 1:
        return _logout_refused("send one logout_token, as a form field")
    try:
        ended = _end_provider_sessions(request, client, tokens[0])
    except sso.SSOError as exc:
        log.warning("refused a logout token: %s", exc)
        return _logout_refused(str(exc))
    if ended:
        log.info("the identity provider ended %d session(s)", len(ended))
    return raw_response(status_code=200, headers={"Cache-Control": "no-store"})


def _logout_refused(why: str) -> HttpResponse:
    return json_response(
        {"error": "invalid_request", "error_description": why},
        status_code=400,
        headers={"Cache-Control": "no-store"},
    )


def _end_provider_sessions(request: HttpRequest, client: sso.OIDCClient, token: str) -> list[str]:
    claims = client.validate_logout(token)  # may fetch the provider's keys
    rt = runtime(request)
    with rt.db.transaction() as tx:
        ended = sso.end_provider_sessions(tx, claims)
    if rt.delegations is not None:
        for session_id in ended:
            rt.delegations.forget(session_id)
    return ended
