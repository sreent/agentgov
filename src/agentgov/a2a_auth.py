"""For agents that serve A2A: take only the calls that came through AgentGov's gateway.

AgentGov checks the calls between agents that pass its gateway, and gives the agent called
a delegation with each one it lets through (the ``X-AgentGov-Delegation`` header): a JWT
it signed (ES256) for that agent, by its name and its AgentGov ID, moments before. A call
that went around the gateway carries none, so an agent that refuses calls without a valid
one takes only calls AgentGov checked (docs/agent-to-agent.md#calls-around-the-gateway)::

    from agentgov.a2a_auth import RequireDelegation

    app = RequireDelegation(
        app, jwks_url="https://agentgov.example.com/v1/delegations/jwks", agent="billing-agent"
    )

It needs only PyJWT (``pyjwt[crypto]``): copy this file into an agent that doesn't install
AgentGov. Any JWT library does the same: ES256, issuer ``agentgov``, audience the agent's
name (or its AgentGov ID), issued in the last minutes, and the keys AgentGov publishes at
``/v1/delegations/jwks``. The agent's card stays open: A2A clients read it before they call.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
import urllib.request
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

import jwt

HEADER = "x-agentgov-delegation"
ISSUER = "agentgov"
ALGORITHM = "ES256"
# Where A2A agents serve their card (and where they did before A2A 0.3).
CARDS = ("/.well-known/agent-card.json", "/.well-known/agent.json")
# The JSON-RPC error a refused call gets (an invalid request, as A2A's are).
REFUSED = -32600

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class DelegationRefused(Exception):
    """A call without a valid delegation from AgentGov: it didn't come through the gateway."""


class PublishedKeys:
    """AgentGov's public keys, read from its JWKS URL and kept ``lifespan`` seconds. A key it
    doesn't know (AgentGov's service token changed) has them read again, at most every
    ``retry`` seconds, so calls with made-up keys can't have AgentGov asked each time; and
    while AgentGov can't be reached, the keys it read last are used."""

    def __init__(self, url: str, *, lifespan: float = 300, retry: float = 30, timeout: float = 5):
        if not url.startswith(("https://", "http://")):
            raise ValueError("AgentGov's keys are read over HTTP(S): give an http(s):// URL")
        self.url = url
        self.lifespan = lifespan
        self.retry = retry
        self.timeout = timeout
        self._keys: dict[str, Any] = {}
        self._read_at: float | None = None
        self._tried_at: float | None = None
        self._lock = threading.Lock()

    def _read(self) -> None:
        # An http(s) URL, checked when it was given.
        request = urllib.request.Request(self.url, headers={"Accept": "application/json"})  # noqa: S310
        with urllib.request.urlopen(request, timeout=self.timeout) as resp:  # noqa: S310
            published = jwt.PyJWKSet.from_dict(json.load(resp))
        self._keys = {key.key_id: key.key for key in published.keys if key.key_id}
        self._read_at = time.monotonic()

    def key(self, kid: str | None) -> Any:
        with self._lock:
            now = time.monotonic()
            stale = self._read_at is None or now - self._read_at > self.lifespan
            unknown = kid not in self._keys
            may_try = self._tried_at is None or now - self._tried_at > self.retry
            if (stale or unknown) and may_try:
                self._tried_at = now
                try:
                    self._read()
                except (OSError, ValueError, jwt.PyJWTError) as exc:
                    if not self._keys:
                        raise DelegationRefused(f"AgentGov's keys can't be read: {exc}") from None
            if kid in self._keys:
                return self._keys[kid]
        raise jwt.InvalidTokenError("signed with a key AgentGov doesn't publish")


class DelegationCheck:
    """Checks the delegation a call carries, with AgentGov's public keys: read from
    ``jwks_url``, or given as ``jwks``. AgentGov issues one for each call it lets through, so
    one issued more than ``max_age`` seconds ago is refused too (None: any until it expires)."""

    def __init__(
        self,
        agent: str,
        *,
        jwks_url: str | None = None,
        jwks: dict[str, Any] | None = None,
        max_age: int | None = 120,
        leeway: int = 30,
    ) -> None:
        if (jwks_url is None) == (jwks is None):
            raise ValueError("give AgentGov's keys as jwks_url or as jwks")
        self.agent = agent
        self.max_age = max_age
        self.leeway = leeway
        self._published = PublishedKeys(jwks_url) if jwks_url else None
        self._given = (
            {key.key_id: key.key for key in jwt.PyJWKSet.from_dict(jwks).keys}
            if jwks is not None
            else {}
        )

    def _key(self, token: str) -> Any:
        kid = jwt.get_unverified_header(token).get("kid")
        if self._published is not None:
            return self._published.key(kid)
        if kid in self._given:
            return self._given[kid]
        raise jwt.InvalidTokenError("signed with a key AgentGov doesn't publish")

    def __call__(self, token: str | None) -> dict[str, Any]:
        """The delegation's claims; DelegationRefused without a valid one."""
        if not token:
            raise DelegationRefused(
                "the call carries no delegation from AgentGov: it didn't come through the gateway"
            )
        try:
            claims = jwt.decode(
                token,
                self._key(token),
                algorithms=[ALGORITHM],
                audience=self.agent,
                issuer=ISSUER,
                leeway=self.leeway,
                options={"require": ["exp", "iat", "jti", "aud", "iss"]},
            )
        except jwt.InvalidTokenError as exc:
            raise DelegationRefused(f"the delegation it carries isn't valid: {exc}") from None
        if self.max_age is not None and time.time() - claims["iat"] > self.max_age + self.leeway:
            raise DelegationRefused(
                "the delegation it carries was given for an earlier call: the gateway gives "
                "one with each call"
            )
        return claims


class RequireDelegation:
    """ASGI middleware: a request without a valid delegation gets 401 and a JSON-RPC error;
    one with gets the delegation's claims in ``scope["state"]["agentgov_delegation"]``.
    The agent's card is served to anyone, as are ``open_paths`` (its health checks, say)."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        agent: str | None = None,
        jwks_url: str | None = None,
        check: DelegationCheck | None = None,
        open_paths: tuple[str, ...] = (),
    ) -> None:
        if check is None:
            if not agent:
                raise ValueError("name the agent the delegations are for, or give a check")
            check = DelegationCheck(agent, jwks_url=jwks_url)
        self.app = app
        self.check = check
        self.open_paths = (*CARDS, *open_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or scope.get("path") in self.open_paths:
            await self.app(scope, receive, send)
            return
        token = None
        for name, value in scope.get("headers") or []:
            if name.decode("latin-1").lower() == HEADER:
                token = value.decode("latin-1")
        try:
            # Reading AgentGov's keys blocks; it happens once every few minutes.
            claims = await asyncio.to_thread(self.check, token)
        except DelegationRefused as exc:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": REFUSED, "message": f"Refused: {exc}"},
                }
            ).encode()
            headers = [(b"content-type", b"application/json")]
            await send({"type": "http.response.start", "status": 401, "headers": headers})
            await send({"type": "http.response.body", "body": body})
            return
        scope.setdefault("state", {})["agentgov_delegation"] = claims
        await self.app(scope, receive, send)
