"""The enterprise MCP registry for developers' MCP clients, and the MCP servers
developers have set up on their machines (docs/developer-tools.md)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import JSONResponse

from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.registry import features, mcp_registry, mcp_sightings
from agentgov.registry.errors import Conflict

# The registry, as GitHub Copilot and VS Code read it: the MCP Registry API, version 0.1,
# without credentials. Its own errors are {"error": "..."}.
public = APIRouter(prefix="/registry/v0.1", tags=["mcp registry"])
router = APIRouter(prefix="/v1/mcp", tags=["mcp"])
read = require(*READ_ROLES)
reporter = require("registrar")  # and admins
CORS = {"Access-Control-Allow-Origin": "*"}


def _answer(body: dict[str, Any], status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=CORS)


def _closed() -> JSONResponse:
    return _answer({"error": "The MCP registry is off (feature mcp-registry)"}, 404)


def _since(value: str | None) -> datetime | None:
    if not value:
        return None
    when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return when if when.tzinfo else when.replace(tzinfo=UTC)


@public.get("/servers")
def list_servers(
    request: Request,
    cursor: str | None = None,
    limit: int | None = None,
    search: str | None = None,
    updated_since: str | None = None,
    version: str | None = None,
    include_deleted: bool = False,
) -> JSONResponse:
    rt = request.app.state.rt
    try:
        since = _since(updated_since)
    except ValueError:
        return _answer({"error": "updated_since must be an RFC 3339 date and time"}, 400)
    with rt.db.session() as s:
        if not features.is_on(s, "mcp-registry"):
            return _closed()
        page = mcp_registry.server_list(
            s,
            rt.settings,
            cursor=cursor,
            limit=limit,
            search=search,
            updated_since=since,
            version_wanted=version,
            include_deleted=include_deleted,
        )
    return _answer(page)


@public.get("/servers/{name:path}/versions/{version}")
def get_version(
    request: Request, name: str, version: str, include_deleted: bool = False
) -> JSONResponse:
    rt = request.app.state.rt
    with rt.db.session() as s:
        if not features.is_on(s, "mcp-registry"):
            return _closed()
        ts = mcp_registry.find(s, rt.settings, name, include_deleted=include_deleted)
        if ts is None or version not in ("latest", mcp_registry.version(ts)):
            return _answer({"error": f"Server {name} version {version} not found"}, 404)
        return _answer(mcp_registry.server_response(ts, rt.settings))


@public.get("/servers/{name:path}/versions")
def list_versions(request: Request, name: str, include_deleted: bool = False) -> JSONResponse:
    """AgentGov keeps one version of each server: its current one."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        if not features.is_on(s, "mcp-registry"):
            return _closed()
        ts = mcp_registry.find(s, rt.settings, name, include_deleted=include_deleted)
        if ts is None:
            return _answer({"error": f"Server {name} not found"}, 404)
        return _answer(
            {"servers": [mcp_registry.server_response(ts, rt.settings)], "metadata": {"count": 1}}
        )


@router.get("/registry")
def registry_view(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """What developers' MCP clients see in the registry, and where they read it."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        servers = mcp_registry.listed(s)
        return {
            "enabled": features.is_on(s, "mcp-registry"),
            "url": f"{rt.settings.public_url.rstrip('/')}/registry",
            "namespace": mcp_registry.namespace(rt.settings),
            "servers": [mcp_registry.server_response(ts, rt.settings) for ts in servers],
        }


@router.get("/managed-settings")
def managed_settings(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """The registry as the allowlist of GitHub Copilot's enterprise managed settings
    (managed-settings.json), which matches servers by URL and command."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        return mcp_registry.managed_settings(s, rt.settings)


@router.post("/sightings")
def report_sightings(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(reporter)
) -> dict[str, int]:
    """One machine and person's MCP servers, as ``agentgov mcp scan --report`` sends them
    (``{"machine", "user", "servers": [...]}``); they replace that machine and person's
    previous report."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        if not features.is_on(s, "mcp-discovery"):
            raise Conflict("discovery of developers' MCP servers is off (feature mcp-discovery)")
        return mcp_sightings.report(
            s,
            rt.settings,
            machine=body.get("machine"),
            user=body.get("user"),
            servers=body.get("servers"),
            actor=principal.actor,
        )


@router.get("/sightings")
def list_sightings(request: Request, _: Principal = Depends(read)) -> list[dict[str, Any]]:
    """Every MCP server developers reported, with how many machines and people have it,
    and whether it is approved."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        return mcp_sightings.view(s, rt.settings)
