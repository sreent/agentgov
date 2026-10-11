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

from fastapi import Depends, FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.responses import Response
from starlette.types import Scope

from agentgov import __version__
from agentgov.api import (
    access_routes,
    copilot_studio_routes,
    feature_routes,
    governance_routes,
    identity_routes,
    instruction_routes,
    integration_routes,
    mcp_routes,
    model_routes,
    platform_routes,
    registry_routes,
    secops_routes,
    sso_routes,
)
from agentgov.api.auth import Principal, signed_in
from agentgov.config import Settings
from agentgov.registry.errors import RegistryError
from agentgov.runtime import Runtime
from agentgov.secops import handoff

log = logging.getLogger(__name__)

# The admin UI renders data that agents and telemetry senders control (names,
# descriptions, reasons), so it only runs its own script and talks to its own API.
UI_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class _UiFiles(StaticFiles):
    async def get_response(self, path: str, scope: Scope) -> Response:
        response = await super().get_response(path, scope)
        response.headers.update(UI_HEADERS)
        return response


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

    @app.exception_handler(RequestValidationError)
    async def request_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Same shape as every other error ({"detail": "..."}), with the field errors kept.
        errors = jsonable_encoder(exc.errors())
        message = "; ".join(
            ".".join(str(p) for p in e.get("loc", []) if p != "body") + f": {e.get('msg')}"
            for e in errors
        )
        return JSONResponse(
            status_code=422, content={"detail": message or "invalid request", "errors": errors}
        )

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
            "sso": {"enabled": settings.sso_enabled, "login_url": "/auth/login"},
            # Signed-in administrators can act in Microsoft 365 through AgentGov.
            "microsoft_admin_actions": settings.microsoft_admin_actions,
        }

    @app.get("/v1/me", tags=["system"])
    def whoami(principal: Principal = Depends(signed_in)) -> dict[str, Any]:
        """The caller's identity and roles, so clients can tailor what they offer."""
        out = principal.describe()
        if "secops" in principal.roles:
            # What the hand-off to security operations lets the secops role do.
            with rt.db.session() as s:
                out["handoff"] = {"level": handoff.level(s), "reached": handoff.reached(s)}
        return out

    app.include_router(registry_routes.router)
    app.include_router(governance_routes.router)
    app.include_router(integration_routes.router)
    app.include_router(sso_routes.router)
    app.include_router(access_routes.router)
    app.include_router(platform_routes.router)
    app.include_router(platform_routes.agent_router)
    app.include_router(instruction_routes.router)
    app.include_router(copilot_studio_routes.router)
    app.include_router(feature_routes.router)
    app.include_router(model_routes.router)
    app.include_router(identity_routes.router)
    app.include_router(secops_routes.router)
    app.include_router(mcp_routes.router)
    app.include_router(mcp_routes.public)

    ui_dir = Path(str(resources.files("agentgov") / "ui"))
    if (ui_dir / "index.html").exists():
        app.mount("/ui", _UiFiles(directory=ui_dir, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        def root() -> RedirectResponse:
            return RedirectResponse("/ui/")

    return app
