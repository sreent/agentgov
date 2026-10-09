"""FastAPI application factory for the control plane."""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib import resources
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from agentgov import __version__
from agentgov.api import governance_routes, integration_routes, registry_routes
from agentgov.config import Settings
from agentgov.registry.errors import RegistryError
from agentgov.runtime import Runtime

log = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None, *, runtime: Runtime | None = None, background: bool = True
) -> FastAPI:
    settings = settings or Settings.from_env()
    if not settings.admin_token and settings.dev_mode:
        settings = settings.with_overrides(admin_token="agt-dev-" + secrets.token_urlsafe(16))
        log.warning("dev mode: generated admin token %s", settings.admin_token)
    rt = runtime or Runtime(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if background:
            rt.start(asyncio.get_running_loop())
        else:
            rt.init_db()
            rt.bundles.bind_loop(asyncio.get_running_loop())
        try:
            yield
        finally:
            if background:
                rt.stop()

    app = FastAPI(
        title="AgentGov control plane",
        version=__version__,
        description="Open-source AI agent governance: registry, lifecycle, policy distribution "
        "and evidence, composed from Keycloak, OPA, agentgateway, Presidio and OpenTelemetry.",
        lifespan=lifespan,
    )
    app.state.rt = rt

    @app.exception_handler(RegistryError)
    async def registry_error(_: Request, exc: RegistryError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})

    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"])
    def readyz() -> dict[str, Any]:
        with rt.db.session() as s:
            s.execute(text("SELECT 1"))
        return {"status": "ready", "version": __version__}

    @app.get("/v1/info", tags=["health"])
    def info() -> dict[str, Any]:
        return {
            "version": __version__,
            "gateway_url": settings.gateway_public_url,
            "identity_provider": "keycloak" if settings.keycloak_enabled else None,
            "token_endpoint": (
                settings.keycloak_issuer.rstrip("/") + "/protocol/openid-connect/token"
                if settings.keycloak_issuer
                else None
            ),
            "audience": settings.gateway_audience,
            "opa": bool(settings.opa_url),
            "unknown_agent_mode": settings.unknown_agent_mode,
        }

    app.include_router(registry_routes.router)
    app.include_router(governance_routes.router)
    app.include_router(integration_routes.router)

    ui_dir = Path(str(resources.files("agentgov") / "ui"))
    if (ui_dir / "index.html").exists():
        app.mount("/ui", StaticFiles(directory=ui_dir, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        def root() -> RedirectResponse:
            return RedirectResponse("/ui/")

    return app
