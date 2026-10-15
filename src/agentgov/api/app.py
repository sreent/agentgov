"""The control plane's ASGI application: Django serves the API and its documentation
(agentgov.web, docs/adr/0007-django.md), the admin UI's files go as they are, and the
runtime runs while the application does."""

from __future__ import annotations

import asyncio
import logging
import secrets
import traceback
from importlib import resources
from pathlib import Path
from types import SimpleNamespace

from starlette.datastructures import URL
from starlette.exceptions import HTTPException
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.staticfiles import StaticFiles
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocketClose

from agentgov import web
from agentgov.config import Settings
from agentgov.runtime import Runtime
from agentgov.web.api import routes as web_routes

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


# The admin UI, built from ui/ into the package (npm run build there), and where it is.
UI_DIR = Path(str(resources.files("agentgov") / "ui"))
UI_PATH = "/ui"

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
) -> ControlPlane:
    settings = settings or Settings.from_env()
    if not settings.admin_token and settings.dev_mode:
        settings = settings.with_overrides(admin_token="agt-dev-" + secrets.token_urlsafe(16))
        log.warning("dev mode: generated admin token %s", settings.admin_token)
    return ControlPlane(runtime or Runtime(settings), background=background)


class ControlPlane:
    """The ASGI app: Django serves the API (agentgov.web), and the admin UI's files go as
    they are. While the app runs, so does the runtime: all of it with ``background``, else
    only its database (as tests want it)."""

    def __init__(self, rt: Runtime, *, background: bool = True) -> None:
        self.state = SimpleNamespace(rt=rt)
        self.background = background
        self.django = web.handler()
        self.ui = _UiFiles(directory=UI_DIR, html=True, check_dir=False)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
        elif scope["type"] == "http":
            await self._http(scope, receive, send)
        else:  # no WebSockets here
            await WebSocketClose()(scope, receive, send)

    async def _http(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope["path"]
        if web.serves(path):
            await self.django({**scope, web.RUNTIME: self.state.rt}, receive, send)
            return
        if path.startswith(UI_PATH + "/"):
            await self._ui(scope, receive, send)
            return
        other = path.rstrip("/") if path.endswith("/") else path + "/"
        if path != "/" and (web.serves(other) or other == UI_PATH + "/"):
            # A path with slashes at its end, or without one, that is served the other way.
            url = URL(scope={**scope, "path": other})
            await RedirectResponse(str(url))(scope, receive, send)
            return
        await _refused(404, "Not Found")(scope, receive, send)

    async def _ui(self, scope: Scope, receive: Receive, send: Send) -> None:
        mounted = {**scope, "root_path": scope.get("root_path", "") + UI_PATH}
        try:
            await self.ui(mounted, receive, send)
        except HTTPException as exc:
            await _refused(exc.status_code, exc.detail)(scope, receive, send)

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        # As Starlette ran FastAPI's lifespan: what fails is said, then raised.
        rt = self.state.rt
        started = False
        await receive()  # lifespan.startup
        try:
            loop = asyncio.get_running_loop()
            if self.background:
                rt.start(loop)
            else:
                rt.init_db()
                rt.bundles.bind_loop(loop)
            try:
                await send({"type": "lifespan.startup.complete"})
                started = True
                await receive()  # lifespan.shutdown
            finally:
                if self.background:
                    rt.stop()
        except BaseException:
            failed = "lifespan.shutdown.failed" if started else "lifespan.startup.failed"
            await send({"type": failed, "message": traceback.format_exc()})
            raise
        await send({"type": "lifespan.shutdown.complete"})


def _refused(status: int, detail: str) -> Response:
    # As the API refuses: {"detail": ...}.
    return JSONResponse({"detail": detail}, status_code=status)


def api_routes(app: ControlPlane) -> list[tuple[str, str]]:
    """Every route of ``app``'s API, as (method, path)."""
    del app  # every control plane serves the one API (agentgov.web)
    return sorted(set(web_routes()))
