"""The control plane's HTTP layer on Django and Django Ninja (docs/adr/0007-django.md),
behind the ASGI app ``agentgov.api.app.create_app`` makes.

It answers as FastAPI did when it served the API (tests/fastapi_answers.py), so callers
notice no difference. Each route runs in a transaction of its own, which Django runs
(agentgov.db); the models are SQLAlchemy's until the ADR's second stage moves them to Django.
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
    """Django's settings, once per process: the HTTP layer, and the databases, which
    agentgov.db adds as it opens them (nothing else keeps state: no Django sessions, users
    or messages)."""
    if settings.configured:
        return
    settings.configure(
        DEBUG=False,
        # Nothing here signs anything: no Django sessions, messages or CSRF tokens.
        SECRET_KEY=secrets.token_urlsafe(50),
        # As with FastAPI: the control plane answers whatever host it is called by.
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF="agentgov.web.urls",
        # The database's tables, as Django models (agentgov.db.models).
        INSTALLED_APPS=["agentgov.db"],
        MIDDLEWARE=[],
        # The databases are added as they are opened (agentgov.db), and the models use the
        # one whose transaction is open.
        DATABASES={},
        DATABASE_ROUTERS=["agentgov.db.Router"],
        # Index names longer than Oracle's 30 characters, the existing indexes': AgentGov
        # runs on SQLite and PostgreSQL (63).
        SILENCED_SYSTEM_CHECKS=["models.E034"],
        USE_TZ=True,
        # The routes bound what they read themselves, as they did with FastAPI.
        DATA_UPLOAD_MAX_MEMORY_SIZE=None,
        DATA_UPLOAD_MAX_NUMBER_FIELDS=None,
        APPEND_SLASH=False,
        # AgentGov's own logging stays as it is.
        LOGGING_CONFIG=None,
    )
    django.setup(set_prefix=False)
    # Django logs every 4xx and 5xx answer: refused calls are the API working, and the server
    # logs what fails, as it did with FastAPI (agentgov.web.asgi).
    logging.getLogger("django.request").setLevel(logging.CRITICAL)


# Before anything here imports Django Ninja, which reads the settings as it loads.
configure()


@cache
def handler() -> Any:
    """Django's ASGI handler, which serves the routes that have moved (agentgov.web.urls)."""
    configure()
    # The routes, registered now: before the first request, for whatever lists them.
    from agentgov.web import urls  # noqa: F401
    from agentgov.web.asgi import Handler

    return Handler()


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
