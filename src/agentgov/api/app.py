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
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.responses import Response
from starlette.types import Scope

from agentgov import __version__
from agentgov.api import (
    access_routes,
    assertion_routes,
    authzen_routes,
    copilot_studio_routes,
    evidence_routes,
    feature_routes,
    governance_routes,
    identity_routes,
    instruction_routes,
    integration_routes,
    mcp_routes,
    model_routes,
    package_routes,
    platform_routes,
    registry_routes,
    rule_routes,
    secops_routes,
    sso_routes,
)
from agentgov.api.auth import Principal, describe, signed_in
from agentgov.config import Settings
from agentgov.identity import chains
from agentgov.registry.errors import RegistryError
from agentgov.runtime import Runtime

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


# The admin UI, built from ui/ into the package (npm run build there).
UI_DIR = Path(str(resources.files("agentgov") / "ui"))

# What /ui/ shows where the package has no admin UI built in it: a source checkout, before
# its UI is built.
UI_MISSING = (
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>AgentGov</title></head>'
    "<body><h1>The admin center isn't built here</h1><p>This control plane's package has no "
    "admin UI in it. Build it in the repository's <code>ui</code> folder with "
    "<code>npm ci &amp;&amp; npm run build</code>, then load this page again. The API is at "
    '<a href="../docs">/docs</a>.</p></body></html>'
)


class _UiFiles(StaticFiles):
    async def check_config(self) -> None:
        # Not built (yet): get_response says so, rather than failing.
        if Path(str(self.directory)).is_dir():
            await super().check_config()

    async def get_response(self, path: str, scope: Scope) -> Response:
        built = (Path(str(self.directory)) / "index.html").is_file()
        if not built and path in {".", "index.html"} and scope["method"] in {"GET", "HEAD"}:
            response: Response = HTMLResponse(UI_MISSING)
        else:
            response = await super().get_response(path, scope)
        response.headers.update(UI_HEADERS)
        # The build names its scripts and styles after their content (assets/index-1a2b3c.js),
        # so they never change; the page naming them is checked each time, so that after an
        # upgrade it doesn't name ones that are gone.
        unchanging = Path(path).parts[:1] == ("assets",) and response.status_code in (200, 304)
        response.headers["Cache-Control"] = (
            "public, max-age=31536000, immutable" if unchanging else "no-cache"
        )
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

    delegation_keys = chains.keys(settings.key_secret)

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
            # What the tokens of the identity issuers the gateway trusts carry, unless an
            # issuer names an audience of its own.
            "issuer_audience": settings.gateway_public_url.rstrip("/"),
            "opa": bool(settings.opa_url),
            "sso": {"enabled": settings.sso_enabled, "login_url": "/auth/login"},
            # Signed-in administrators can act in Microsoft 365 through AgentGov.
            "microsoft_admin_actions": settings.microsoft_admin_actions,
            # IBM Granite Guardian, for agent instructions and traffic (docs/detection.md).
            "classifier": {
                "enabled": bool(settings.guardian_url),
                "model": settings.guardian_model if settings.guardian_url else None,
            },
            # Where agents find the keys to check the delegations AgentGov gives them.
            "delegation_jwks": "/v1/delegations/jwks" if delegation_keys else None,
            # The transparency log the ledger's checkpoints go into (docs/evidence.md).
            "transparency_log": settings.ledger_rekor_url,
        }

    @app.get("/v1/delegations/jwks", tags=["health"])
    def delegation_jwks() -> Response:
        """The public keys of the delegations AgentGov gives the agents it calls through the
        gateway: an agent that checks the one each call carries refuses calls around the
        gateway (docs/agent-to-agent.md#calls-around-the-gateway). No secret."""
        return JSONResponse(
            chains.jwks(delegation_keys), headers={"Cache-Control": "public, max-age=300"}
        )

    @app.get("/v1/me", tags=["system"])
    def whoami(principal: Principal = Depends(signed_in)) -> dict[str, Any]:
        """The caller's identity and roles, so clients can tailor what they offer."""
        return describe(rt, principal)

    app.include_router(registry_routes.router)
    app.include_router(package_routes.router)
    app.include_router(rule_routes.router)
    app.include_router(governance_routes.router)
    app.include_router(evidence_routes.router)
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
    app.include_router(authzen_routes.router)
    app.include_router(assertion_routes.router)

    app.mount("/ui", _UiFiles(directory=UI_DIR, html=True, check_dir=False), name="ui")

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/ui/")

    return app
