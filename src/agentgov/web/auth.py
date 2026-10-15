"""Who is calling, for the routes Django serves: the very rules of ``agentgov.api.auth``
(tokens, API keys, single sign-on sessions, the CSRF header, the internal listener), applied
to Django's requests while routes move."""

from __future__ import annotations

from collections.abc import Callable
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


def signed_in(request: HttpRequest) -> Principal:
    """Anyone authenticated, whatever their role (else 401)."""
    return auth.signed_in(_Request(request))  # type: ignore[arg-type]


def require(*roles: str, admin: bool = True) -> Callable[[HttpRequest], Principal]:
    """Whoever holds one of ``roles`` for every team, or is an administrator (unless
    ``admin`` is false: then ``roles`` alone); else 401 or 403."""
    check = auth.require(*roles, admin=admin)
    return lambda request: check(_Request(request))  # type: ignore[arg-type]


async def asigned_in(request: HttpRequest) -> Principal:
    """``signed_in``, for async views: off the event loop, as it may read the database."""
    return await sync_to_async(signed_in, thread_sensitive=False, executor=VIEWS)(request)
