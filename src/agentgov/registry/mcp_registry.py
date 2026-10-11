"""AgentGov's tool servers as an MCP registry, for developers' MCP clients.

GitHub Copilot (in VS Code, Visual Studio, JetBrains, Eclipse and Xcode, and its
CLI) and VS Code read an organisation's MCP registry: an HTTP API in the MCP
Registry format, version 0.1. In its "Registry only" mode, Copilot lets
developers run only the servers the registry lists. AgentGov serves the tool
servers listed for developers (``developers``), at ``/registry/v0.1/...``:

* servers agents call through the gateway, with the gateway's address;
* servers only for developers (``gateway`` off), with their own address or the
  packages developers run on their machines (``packages``).

The registry is read without credentials, as the clients read it, and only
while the ``mcp-registry`` feature is on. ``managed_settings`` writes the same
list as the allowlist of Copilot's enterprise managed settings, which matches
servers by URL and command rather than by name.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids
from agentgov.config import Settings
from agentgov.models import BLOCKED, ToolServer

API_VERSION = "v0.1"
SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
OFFICIAL = "io.modelcontextprotocol.registry/official"
META = "dev.agentgov/server"
MAX_LIMIT = 100


def namespace(settings: Settings) -> str:
    """The registry names' namespace: AGENTGOV_MCP_REGISTRY_NAMESPACE, or the control
    plane's host name reversed ("agentgov.contoso.com" is "com.contoso.agentgov")."""
    if settings.mcp_registry_namespace:
        return settings.mcp_registry_namespace
    host = urlsplit(settings.public_url).hostname or ""
    return ".".join(reversed(host.split("."))) if "." in host else "local.agentgov"


def registry_name(ts: ToolServer, settings: Settings) -> str:
    return ts.registry_name or f"{namespace(settings)}/{ts.name}"


def version(ts: ToolServer) -> str:
    """Changes developers' clients should pick up bump the patch version."""
    return f"1.0.{ts.revision or 0}"


def gateway_url(ts: ToolServer, settings: Settings) -> str:
    return f"{settings.gateway_public_url.rstrip('/')}/mcp/{ts.name}"


def package_command(package: dict[str, Any]) -> list[str]:
    """The command developers run for a package, as the managed-settings allowlist
    matches it: the package's own ``command``, or the usual launcher's."""
    if package.get("command"):
        return list(package["command"])
    identifier, ver = package["identifier"], package.get("version")
    kind = package["registry_type"]
    if kind == "npm":
        return ["npx", f"{identifier}@{ver}" if ver else identifier]
    if kind == "pypi":
        return ["uvx", f"{identifier}=={ver}" if ver else identifier]
    if kind == "oci":
        return ["docker", "run", "-i", "--rm", f"{identifier}:{ver}" if ver else identifier]
    if kind == "nuget":
        return ["dnx", f"{identifier}@{ver}" if ver else identifier, "--yes"]
    return [identifier]


def _description(ts: ToolServer) -> str:
    text = " ".join((ts.description or "").split()) or f"The {ts.name} MCP server"
    return text if len(text) <= 100 else text[:99].rstrip() + "…"


def server_detail(ts: ToolServer, settings: Settings) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "$schema": SCHEMA,
        "name": registry_name(ts, settings),
        "title": ts.name,
        "description": _description(ts),
        "version": version(ts),
    }
    url = gateway_url(ts, settings) if ts.gateway else ts.url
    if url:
        detail["remotes"] = [{"type": "streamable-http", "url": url}]
    if ts.packages:
        detail["packages"] = [
            {
                "registryType": p["registry_type"],
                "identifier": p["identifier"],
                **({"version": p["version"]} if p.get("version") else {}),
                "transport": {"type": "stdio"},
            }
            for p in ts.packages
        ]
    detail["_meta"] = {
        META: {
            "owner": ts.owner,
            "trustLevel": ts.trust_level,
            "dataClassification": ts.data_classification,
            "throughGateway": bool(ts.gateway),
        }
    }
    return detail


def server_response(ts: ToolServer, settings: Settings) -> dict[str, Any]:
    status = "deleted" if ts.status == BLOCKED else "active"
    return {
        "server": server_detail(ts, settings),
        "_meta": {
            OFFICIAL: {
                "status": status,
                "publishedAt": ids.isoformat(ts.created_at),
                "updatedAt": ids.isoformat(ts.updated_at),
                "isLatest": True,
            }
        },
    }


def listed(session: Session, *, include_deleted: bool = False) -> list[ToolServer]:
    """The tool servers in the registry: listed and approved (or blocked, as deleted)."""
    statuses = ["approved", BLOCKED] if include_deleted else ["approved"]
    return list(
        session.scalars(
            select(ToolServer)
            .where(ToolServer.developers.is_(True), ToolServer.status.in_(statuses))
            .order_by(ToolServer.name)
        )
    )


def _cursor(name: str) -> str:
    return base64.urlsafe_b64encode(name.encode()).decode().rstrip("=")


def _after(cursor: str | None) -> str | None:
    if not cursor:
        return None
    try:
        return base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
    except (ValueError, UnicodeDecodeError):
        return None


def server_list(
    session: Session,
    settings: Settings,
    *,
    cursor: str | None = None,
    limit: int | None = None,
    search: str | None = None,
    updated_since: datetime | None = None,
    version_wanted: str | None = None,
    include_deleted: bool = False,
) -> dict[str, Any]:
    """``GET /v0.1/servers``: one page of the registry, by name."""
    servers = listed(session, include_deleted=include_deleted or updated_since is not None)
    rows = [(registry_name(ts, settings), ts) for ts in servers]
    rows.sort(key=lambda r: r[0])
    if search:
        rows = [r for r in rows if search.lower() in r[0].lower()]
    if updated_since is not None:
        rows = [r for r in rows if r[1].updated_at and r[1].updated_at >= updated_since]
    if version_wanted and version_wanted != "latest":
        rows = [r for r in rows if version(r[1]) == version_wanted]
    after = _after(cursor)
    if after:
        rows = [r for r in rows if r[0] > after]
    size = min(max(limit or 30, 1), MAX_LIMIT)
    page = rows[:size]
    more = len(rows) > size
    return {
        "servers": [server_response(ts, settings) for _, ts in page],
        "metadata": {"count": len(page), **({"nextCursor": _cursor(page[-1][0])} if more else {})},
    }


def find(
    session: Session, settings: Settings, name: str, *, include_deleted: bool = False
) -> ToolServer | None:
    for ts in listed(session, include_deleted=include_deleted):
        if registry_name(ts, settings) == name:
            return ts
    return None


def managed_settings(session: Session, settings: Settings) -> dict[str, Any]:
    """The registry as Copilot's enterprise managed-settings allowlist."""
    allowed: list[dict[str, Any]] = []
    for ts in listed(session):
        url = gateway_url(ts, settings) if ts.gateway else ts.url
        if url:
            allowed.append({"serverUrl": url})
        for package in ts.packages or []:
            allowed.append({"serverCommand": package_command(package)})
    return {"allowedMcpServers": allowed}
