"""The routes Django serves (agentgov.web): the API's groups that have moved."""

from __future__ import annotations

from django.urls import include, path

from agentgov.web import health
from agentgov.web.api import api

api.add_router("", health.router)

# Ninja's own root (its docs page, off here) left out: "/" is the admin UI's.
patterns, app_name, namespace = api.urls
urlpatterns = [
    path(
        "", include(([p for p in patterns if p.name != "api-root"], app_name), namespace=namespace)
    )
]
