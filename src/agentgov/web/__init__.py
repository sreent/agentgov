"""The control plane's HTTP layer on Django and Django Ninja (docs/adr/0007-django.md).

Routes move here from FastAPI (agentgov.api) a group at a time. Until a group has moved,
FastAPI serves it, behind the one ASGI app ``agentgov.api.app.create_app`` makes; data stays
in SQLAlchemy for this stage, each route in a transaction of its own as before.
"""

from __future__ import annotations

import logging
import secrets
from functools import cache, lru_cache
from typing import Any

import django
from django.conf import settings

# Where the composed app puts the runtime in each request's ASGI scope: a process can hold
# several control planes (the tests do), each with a runtime of its own.
RUNTIME = "agentgov.runtime"


def configure() -> None:
    """Django's settings, once per process: the HTTP layer only, with nothing that keeps
    state of its own (no Django sessions, users, messages or database yet)."""
    if settings.configured:
        return
    settings.configure(
        DEBUG=False,
        # Nothing here signs anything: no Django sessions, messages or CSRF tokens.
        SECRET_KEY=secrets.token_urlsafe(50),
        # As with FastAPI: the control plane answers whatever host it is called by.
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF="agentgov.web.urls",
        INSTALLED_APPS=[],
        MIDDLEWARE=[],
        DATABASES={},
        USE_TZ=True,
        # The routes bound what they read themselves, as they did with FastAPI.
        DATA_UPLOAD_MAX_MEMORY_SIZE=None,
        DATA_UPLOAD_MAX_NUMBER_FIELDS=None,
        APPEND_SLASH=False,
        # AgentGov's own logging stays as it is.
        LOGGING_CONFIG=None,
    )
    django.setup(set_prefix=False)
    # Django logs every 4xx answer as a warning: refused calls are the API working.
    logging.getLogger("django.request").setLevel(logging.ERROR)


@cache
def handler() -> Any:
    """Django's ASGI handler, which serves the routes that have moved (agentgov.web.urls)."""
    configure()
    from django.core.handlers.asgi import ASGIHandler

    # The routes, registered now: before the first request, for whatever lists them.
    from agentgov.web import urls  # noqa: F401

    return ASGIHandler()


@lru_cache(maxsize=4096)
def serves(path: str) -> bool:
    """Whether a route has moved to Django: its URL configuration resolves the path."""
    configure()
    from django.urls import Resolver404, resolve

    try:
        resolve(path)
    except Resolver404:
        return False
    return True
