"""The routes Django serves (agentgov.web): the API's groups that have moved, in the order
FastAPI had them (where two routes take a path, the first serves it)."""

from __future__ import annotations

from django.urls import include, path

from agentgov.web import (
    access,
    assertions,
    authzen,
    copilot_studio,
    evidence,
    features,
    governance,
    health,
    identity,
    instructions,
    integration,
    mcp,
    model_providers,
    packages,
    platforms,
    registry,
    rules,
    secops,
)
from agentgov.web.api import api

for router in (
    health.router,
    registry.router,
    packages.router,
    rules.router,
    governance.router,
    evidence.router,
    integration.router,
    access.router,
    platforms.router,
    platforms.agent_router,
    instructions.router,
    copilot_studio.router,
    features.router,
    model_providers.router,
    identity.router,
    secops.router,
    mcp.router,
    mcp.public,
    authzen.router,
    assertions.router,
):
    api.add_router("", router)

# Ninja's own root (its docs page, off here) left out: "/" is the admin UI's.
patterns, app_name, namespace = api.urls
urlpatterns = [
    path(
        "", include(([p for p in patterns if p.name != "api-root"], app_name), namespace=namespace)
    )
]
