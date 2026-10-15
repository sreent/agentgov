"""The enterprise MCP registry for developers' MCP clients, and the MCP servers
developers have set up on their machines (docs/developer-tools.md)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from django.http import HttpRequest, HttpResponse
from ninja import Body

from agentgov.api.auth import READ_ROLES
from agentgov.registry import features, mcp_registry, mcp_sightings
from agentgov.registry.errors import Conflict
from agentgov.web.api import Router, json_response
from agentgov.web.auth import require, runtime

# The registry, as GitHub Copilot and VS Code read it: the MCP Registry API, version 0.1,
# without credentials. Its own errors are {"error": "..."}.
public = Router(tags=["mcp registry"])
router = Router(tags=["mcp"])
read = require(*READ_ROLES)
reporter = require("registrar")  # and admins
CORS = {"Access-Control-Allow-Origin": "*"}


def _answer(body: dict[str, Any], status: int = 200) -> HttpResponse:
    return json_response(body, status, headers=CORS)


def _closed() -> HttpResponse:
    return _answer({"error": "The MCP registry is off (feature mcp-registry)"}, 404)


def _since(value: str | None) -> datetime | None:
    if not value:
        return None
    when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return when if when.tzinfo else when.replace(tzinfo=UTC)


@public.get("/registry/v0.1/servers")
def list_servers(
    request: HttpRequest,
    cursor: str | None = None,
    limit: int | None = None,
    search: str | None = None,
    updated_since: str | None = None,
    version: str | None = None,
    include_deleted: bool = False,
) -> HttpResponse:
    rt = runtime(request)
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


@public.get("/registry/v0.1/servers/{path:name}/versions/{version}")
def get_version(
    request: HttpRequest, name: str, version: str, include_deleted: bool = False
) -> HttpResponse:
    rt = runtime(request)
    with rt.db.session() as s:
        if not features.is_on(s, "mcp-registry"):
            return _closed()
        ts = mcp_registry.find(s, rt.settings, name, include_deleted=include_deleted)
        if ts is None or version not in ("latest", mcp_registry.version(ts)):
            return _answer({"error": f"Server {name} version {version} not found"}, 404)
        return _answer(mcp_registry.server_response(ts, rt.settings))


@public.get("/registry/v0.1/servers/{path:name}/versions")
def list_versions(request: HttpRequest, name: str, include_deleted: bool = False) -> HttpResponse:
    """AgentGov keeps one version of each server: its current one."""
    rt = runtime(request)
    with rt.db.session() as s:
        if not features.is_on(s, "mcp-registry"):
            return _closed()
        ts = mcp_registry.find(s, rt.settings, name, include_deleted=include_deleted)
        if ts is None:
            return _answer({"error": f"Server {name} not found"}, 404)
        return _answer(
            {"servers": [mcp_registry.server_response(ts, rt.settings)], "metadata": {"count": 1}}
        )


@router.get("/v1/mcp/registry", auth=read)
def registry_view(request: HttpRequest) -> dict[str, Any]:
    """What developers' MCP clients see in the registry, and where they read it."""
    rt = runtime(request)
    with rt.db.session() as s:
        servers = mcp_registry.listed(s)
        return {
            "enabled": features.is_on(s, "mcp-registry"),
            "url": f"{rt.settings.public_url.rstrip('/')}/registry",
            "namespace": mcp_registry.namespace(rt.settings),
            "servers": [mcp_registry.server_response(ts, rt.settings) for ts in servers],
        }


@router.get("/v1/mcp/managed-settings", auth=read)
def managed_settings(request: HttpRequest) -> dict[str, Any]:
    """The registry as the allowlist of GitHub Copilot's enterprise managed settings
    (managed-settings.json), which matches servers by URL and command."""
    rt = runtime(request)
    with rt.db.session() as s:
        return mcp_registry.managed_settings(s, rt.settings)


@router.post("/v1/mcp/sightings", auth=reporter)
def report_sightings(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, int]:
    """One machine and person's MCP servers, as ``agentgov mcp scan --report`` sends them
    (``{"machine", "user", "servers": [...]}``); they replace that machine and person's
    previous report."""
    rt = runtime(request)
    with rt.db.session() as s:
        if not features.is_on(s, "mcp-discovery"):
            raise Conflict("discovery of developers' MCP servers is off (feature mcp-discovery)")
        return mcp_sightings.report(
            s,
            rt.settings,
            machine=body.get("machine"),
            user=body.get("user"),
            servers=body.get("servers"),
            actor=request.auth.actor,
        )


@router.get("/v1/mcp/sightings", auth=read)
def list_sightings(request: HttpRequest) -> list[dict[str, Any]]:
    """Every MCP server developers reported, with how many machines and people have it,
    and whether it is approved."""
    rt = runtime(request)
    with rt.db.session() as s:
        return mcp_sightings.view(s, rt.settings)
