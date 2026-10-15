"""Who is calling, for the routes Django serves: the very rules of ``agentgov.api.auth`` and
``agentgov.api.reach`` (tokens, API keys, single sign-on sessions, the CSRF header, the
internal listener, roles for some teams), applied to Django's requests.

A route names its check as its ``auth``, which runs before anything else is read, as
FastAPI's dependencies did; the route reads who is calling as ``request.auth``::

    admin = require("admin")

    @router.post("/v1/things", auth=admin)
    def create(request: HttpRequest) -> dict[str, Any]:
        principal: Principal = request.auth
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any

from asgiref.sync import sync_to_async
from django.http import HttpRequest

from agentgov.api import auth
from agentgov.api.auth import Principal
from agentgov.web import RUNTIME
from agentgov.web.api import VIEWS


def runtime(request: HttpRequest) -> Any:
    """The runtime of the control plane serving this request."""
    return request.scope[RUNTIME]  # type: ignore[attr-defined]


class _Request:
    """What ``agentgov.api.auth`` reads of a request, from Django's."""

    def __init__(self, request: HttpRequest) -> None:
        self.headers = request.headers
        self.cookies = request.COOKIES
        self.method = request.method
        self.scope = getattr(request, "scope", {})
        self.app = SimpleNamespace(state=SimpleNamespace(rt=runtime(request)))


def guard(check: Callable[[Any], Principal]) -> Callable[[HttpRequest], Principal]:
    """A check of ``agentgov.api.auth`` or ``agentgov.api.reach`` (``require``,
    ``signed_in``), as a route's ``auth``: who is calling, else 401 or 403."""

    def guarded(request: HttpRequest) -> Principal:
        return check(_Request(request))

    return guarded


def aguard(check: Callable[[Any], Principal]) -> Callable[[HttpRequest], Awaitable[Principal]]:
    """``guard``, for async routes: the check runs off the event loop, as it reads the
    database."""
    guarded = sync_to_async(guard(check), thread_sensitive=False, executor=VIEWS)

    async def aguarded(request: HttpRequest) -> Principal:
        return await guarded(request)

    return aguarded


def require(*roles: str, admin: bool = True) -> Callable[[HttpRequest], Principal]:
    """Whoever holds one of ``roles`` for every team, or is an administrator (unless
    ``admin`` is false: then ``roles`` alone)."""
    return guard(auth.require(*roles, admin=admin))


def arequire(*roles: str, admin: bool = True) -> Callable[[HttpRequest], Awaitable[Principal]]:
    """``require``, for async routes."""
    return aguard(auth.require(*roles, admin=admin))


signed_in = guard(auth.signed_in)


def session_principal(request: HttpRequest) -> Principal | None:
    """The person signed in through single sign-on, from the session cookie."""
    return auth.session_principal(_Request(request))  # type: ignore[arg-type]
