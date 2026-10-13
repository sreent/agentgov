"""MCP tool servers published through the gateway, with a governed tool catalog.

The catalog is learned from ``tools/list`` responses observed by the
governance processor. Each tool definition is fingerprinted the first time it
is seen (trust on first use). If a server later changes a definition (an MCP
"rug pull"), the tool is flagged and the baseline policy refuses calls to it
until an administrator approves the new definition.

A tool server can also be listed for developers (``developers``), in the MCP
registry their MCP clients read (``agentgov.registry.mcp_registry``): through
the gateway, or, for a server only developers use (``gateway`` off), at its own
address or as packages they run on their machines.

A server outside the gateway that takes access tokens from an authorization server of its
own (``authorization_server``) is one agents reach directly, with an identity assertion
(ID-JAG) AgentGov gives them for it, as their grants allow (``agentgov.identity.assertions``).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.db import lock, mark_changed
from agentgov.models import BLOCKED, PENDING, ToolServer
from agentgov.registry import findings, validation
from agentgov.registry.errors import Conflict, InvalidTransition, NotFound, ValidationError
from agentgov.registry.versions import changes, edited, start_edit

APPROVED = "approved"
FIELDS = (
    "url",
    "description",
    "owner",
    "trust_level",
    "data_classification",
    "labels",
    "gateway",
    "developers",
    "registry_name",
    "packages",
    "authorization_server",
    "oauth_client_id",
)
# What developers' MCP clients see in the registry: a change bumps the server's version there.
REGISTRY_FIELDS = {"url", "description", "gateway", "developers", "registry_name", "packages"}
PACKAGE_TYPES = ("npm", "pypi", "oci", "nuget", "cargo", "mcpb")
# The MCP registry's server names: a namespace, one slash, a name.
REGISTRY_NAME = re.compile(r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$")


def get(session: Session, ref: str) -> ToolServer:
    ts = session.get(ToolServer, ref) or session.scalar(
        select(ToolServer).where(ToolServer.name == ref)
    )
    if ts is None:
        raise NotFound(f"tool server {ref!r} not found")
    return ts


def list_all(session: Session, status: str | None = None) -> list[ToolServer]:
    stmt = select(ToolServer).order_by(ToolServer.name)
    if status:
        stmt = stmt.where(ToolServer.status == status)
    return list(session.scalars(stmt))


def _package(i: int, value: Any) -> dict[str, Any]:
    where = f"packages[{i}]"
    if not isinstance(value, dict) or set(value) - {
        "registry_type",
        "identifier",
        "version",
        "command",
    }:
        raise ValidationError(f"{where} takes registry_type, identifier, version and command")
    kind = validation.one_of(value.get("registry_type"), PACKAGE_TYPES, f"{where}.registry_type")
    identifier = value.get("identifier")
    if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 255:
        raise ValidationError(
            f"{where}.identifier must be the package's name, such as @playwright/mcp"
        )
    package: dict[str, Any] = {"registry_type": kind, "identifier": identifier.strip()}
    version = value.get("version")
    if version not in (None, ""):
        if not isinstance(version, str) or version == "latest" or len(version) > 255:
            raise ValidationError(f"{where}.version must be an exact version, not latest")
        package["version"] = version.strip()
    command = value.get("command")
    if command not in (None, []):
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(c, str) and c for c in command)
        ):
            raise ValidationError(f"{where}.command must be the command line as a list")
        package["command"] = command
    return package


def _apply(ts: ToolServer, data: dict[str, Any]) -> list[str]:
    changed = []
    for key in FIELDS:
        if key not in data:
            continue
        value = data[key]
        if key == "url":
            value = value or ""
            if not isinstance(value, str) or (
                value and not value.startswith(("http://", "https://"))
            ):
                raise ValidationError(
                    "url must be an http(s) URL of a Streamable HTTP MCP endpoint"
                )
        elif key in ("gateway", "developers"):
            if not isinstance(value, bool):
                raise ValidationError(f"{key} must be true or false")
        elif key == "registry_name":
            value = value or None
            if value is not None and (
                not isinstance(value, str) or len(value) > 200 or not REGISTRY_NAME.match(value)
            ):
                raise ValidationError(
                    "registry_name looks like namespace/name, such as com.contoso/crm"
                )
        elif key == "packages":
            if value is None:
                value = []
            if not isinstance(value, list) or len(value) > 20:
                raise ValidationError("packages must be a list of at most 20 packages")
            value = [_package(i, p) for i, p in enumerate(value)]
        elif key == "authorization_server":
            value = validation.issuer_url(value, key)
        elif key == "oauth_client_id":
            value = value or None
            if value is not None and (not isinstance(value, str) or len(value) > 200):
                raise ValidationError("oauth_client_id is a client ID, of at most 200 characters")
        elif key == "trust_level":
            value = validation.trust_level(value)
        elif key == "data_classification":
            value = validation.data_classification(value)
        elif key == "labels":
            value = validation.labels(value)
        elif key in ("description",):
            value = str(value or "")
        if getattr(ts, key) != value:
            setattr(ts, key, value)
            changed.append(key)
    _check(ts)
    if REGISTRY_FIELDS & set(changed) and ts.revision is not None:
        ts.revision += 1
    return changed


def _check(ts: ToolServer) -> None:
    """What a tool server must have, whoever uses it."""
    if ts.authorization_server:
        # Agents reach a server on the gateway through it, with their AgentGov token: an
        # access token of the server's own would let them go around it.
        if ts.gateway:
            raise ValidationError(
                "an authorization server is for servers outside the gateway (gateway: false): "
                "agents reach servers on the gateway through it"
            )
        if not ts.url:
            raise ValidationError("a server with an authorization server needs its url")
    elif ts.oauth_client_id:
        raise ValidationError("oauth_client_id is the client at its authorization_server")
    if not ts.gateway and not ts.developers and not ts.authorization_server:
        raise ValidationError(
            "a tool server is published on the gateway, listed for developers, reached with "
            "identity assertions (an authorization_server), or more than one of these"
        )
    if ts.gateway and not ts.url:
        raise ValidationError("url is required for a server published on the gateway")
    if not ts.gateway and not (ts.url or ts.packages):
        raise ValidationError("a server only for developers needs its url or the packages they run")
    if ts.packages and not ts.developers:
        raise ValidationError("packages are for servers listed for developers (developers: true)")


def _unique_registry_name(session: Session, ts: ToolServer) -> None:
    if ts.registry_name and session.scalar(
        select(ToolServer).where(
            ToolServer.registry_name == ts.registry_name, ToolServer.id != ts.id
        )
    ):
        raise Conflict(f"another tool server is already {ts.registry_name!r} in the registry")


def create(session: Session, data: dict[str, Any], *, actor: str, approve: bool) -> ToolServer:
    """Register a server. Requests from non-admins start ``pending`` review."""
    name = validation.slug(data.get("name"), "name")
    if session.scalar(select(ToolServer).where(ToolServer.name == name)):
        raise Conflict(f"tool server {name!r} already exists")
    ts = ToolServer(
        id=ids.new_id(ids.TOOL_SERVER),
        name=name,
        url="",
        status=APPROVED if approve else PENDING,
        labels={},
        tools=[],
        gateway=True,
        developers=False,
        packages=[],
        revision=0,
        created_by=actor,
    )
    _apply(ts, data)
    ts.revision = 0
    _unique_registry_name(session, ts)
    session.add(ts)
    session.flush()
    ledger.append(
        session,
        type="toolserver.registered",
        actor=actor,
        resource=f"toolserver/{name}",
        details={
            "url": ts.url or None,
            "status": ts.status,
            "trust_level": ts.trust_level,
            "gateway": ts.gateway,
            "developers": ts.developers,
        },
    )
    mark_changed(session, "toolservers")
    return ts


def update(
    session: Session,
    ts: ToolServer,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
) -> list[str]:
    start_edit(session, ts, version, f"tool server {ts.name}")
    changed = _apply(ts, data)
    _unique_registry_name(session, ts)
    if changed:
        edited(ts)
        ledger.append(
            session,
            type="toolserver.updated",
            actor=actor,
            resource=f"toolserver/{ts.name}",
            details={**{k: getattr(ts, k) for k in changed}, "changes": changes(ts)},
        )
        mark_changed(session, "toolservers")
    return changed


def set_status(session: Session, ts: ToolServer, action: str, *, actor: str) -> ToolServer:
    targets = {"approve": APPROVED, "block": BLOCKED, "unblock": APPROVED}
    if action not in targets:
        raise ValidationError(f"unknown action {action!r}")
    lock(session, ts)
    if action == "unblock" and ts.status != BLOCKED:
        raise InvalidTransition("tool server is not blocked")
    if action == "approve" and ts.status != PENDING:
        raise InvalidTransition("tool server is not pending approval")
    previous, target = ts.status, targets[action]
    if action == "unblock":
        # As it was when it was blocked: blocking then unblocking approves nothing.
        target = ts.blocked_from or target
    if target == BLOCKED:
        # Blocked again, it was still what it was before the first block.
        ts.blocked_from = ts.blocked_from if previous == BLOCKED else previous
    else:
        ts.blocked_from = None
    ts.status = target
    ledger.append(
        session,
        type=f"toolserver.{action}",
        actor=actor,
        resource=f"toolserver/{ts.name}",
        severity="warning" if action == "block" else "info",
        details={"from": previous, "to": ts.status},
    )
    mark_changed(session, "toolservers")
    return ts


def delete(session: Session, ts: ToolServer, *, actor: str) -> None:
    ledger.append(session, type="toolserver.deleted", actor=actor, resource=f"toolserver/{ts.name}")
    session.delete(ts)
    mark_changed(session, "toolservers")


def fingerprint(tool: dict[str, Any]) -> str:
    material = {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema"),
        "annotations": tool.get("annotations"),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def record_catalog(
    session: Session,
    ts: ToolServer,
    tools: list[dict[str, Any]],
    *,
    poisoned: dict[str, list[str]] | None = None,
) -> dict[str, list[str]]:
    """Merge an observed ``tools/list`` result into the catalog.

    ``poisoned`` maps tool names to reasons the processor flagged them.
    Returns the names of added, changed and poisoned tools.
    """
    poisoned = poisoned or {}
    now = ids.isoformat(ids.utcnow())
    catalog = {t["name"]: dict(t) for t in ts.tools or []}
    before = {n: _policy_view(t) for n, t in catalog.items()}
    report: dict[str, list[str]] = {"added": [], "changed": [], "poisoned": []}
    for tool in tools:
        name = tool.get("name")
        if not isinstance(name, str):
            continue
        fp = fingerprint(tool)
        entry = catalog.get(name)
        if entry is None:
            entry = {"name": name, "first_seen": now, "approved_fingerprint": fp}
            report["added"].append(name)
        if fp == entry.get("approved_fingerprint"):
            entry["changed_at"] = None
        elif fp != entry.get("fingerprint"):
            # A new, unapproved definition (repeat observations are not re-reported).
            entry["changed_at"] = now
            report["changed"].append(name)
        if name in poisoned and not entry.get("poisoned"):
            report["poisoned"].append(name)
        entry.update(
            {
                "description": (tool.get("description") or "")[:2000],
                "annotations": tool.get("annotations") or {},
                "fingerprint": fp,
                "last_seen": now,
                "poisoned": name in poisoned,
                "poisoning_reasons": poisoned.get(name, []),
            }
        )
        catalog[name] = entry
    ts.tools = sorted(catalog.values(), key=lambda t: t["name"])
    ts.tools_synced_at = ids.utcnow()

    for name in report["changed"]:
        findings.raise_finding(
            session,
            type="toolserver.tool_drift",
            severity="high",
            subject=f"{ts.name}/{name}",
            category=findings.THREAT,
            title=f"Tool definition changed: {ts.name}/{name}",
            description="The server now advertises a different definition for this tool than the "
            "one approved. Calls are refused until the new definition is approved.",
            remediation=f"Review the new definition, then approve it: POST "
            f"/v1/toolservers/{ts.name}/tools/{name}/approve",
        )
    for name in report["poisoned"]:
        findings.raise_finding(
            session,
            type="toolserver.tool_poisoning",
            severity="critical",
            subject=f"{ts.name}/{name}",
            category=findings.THREAT,
            title=f"Possible tool poisoning: {ts.name}/{name}",
            description="; ".join(poisoned[name]),
            remediation="The tool is hidden from agents. Investigate the server and block it "
            "if the definition is malicious.",
        )
    if any(report.values()):
        ledger.append(
            session,
            type="toolserver.catalog_changed",
            actor="service:processor",
            resource=f"toolserver/{ts.name}",
            severity="warning" if report["changed"] or report["poisoned"] else "info",
            details=report,
        )
    if {n: _policy_view(t) for n, t in catalog.items()} != before:
        mark_changed(session, "toolservers")
    return report


def _policy_view(entry: dict[str, Any]) -> tuple[Any, ...]:
    """The catalog fields OPA policies depend on."""
    return (
        entry.get("fingerprint"),
        entry.get("approved_fingerprint"),
        bool(entry.get("changed_at")),
        bool(entry.get("poisoned")),
        json.dumps(entry.get("annotations") or {}, sort_keys=True),
    )


def approve_tool(session: Session, ts: ToolServer, tool_name: str, *, actor: str) -> dict[str, Any]:
    """Accept a tool's current definition as the approved one."""
    catalog = [dict(t) for t in ts.tools or []]
    for entry in catalog:
        if entry["name"] == tool_name:
            entry["approved_fingerprint"] = entry.get("fingerprint")
            entry["changed_at"] = None
            ts.tools = catalog
            ledger.append(
                session,
                type="toolserver.tool_approved",
                actor=actor,
                resource=f"toolserver/{ts.name}/{tool_name}",
                details={"fingerprint": entry["approved_fingerprint"]},
            )
            mark_changed(session, "toolservers")
            return entry
    raise NotFound(f"tool {tool_name!r} is not in the {ts.name} catalog")


def to_dict(ts: ToolServer, gateway_url: str | None = None) -> dict[str, Any]:
    return {
        "id": ts.id,
        "name": ts.name,
        "version": ts.version,
        "url": ts.url or None,
        "gateway_url": (
            f"{gateway_url.rstrip('/')}/mcp/{ts.name}" if gateway_url and ts.gateway else None
        ),
        "gateway": ts.gateway,
        "developers": ts.developers,
        "registry_name": ts.registry_name,
        "packages": ts.packages or [],
        "authorization_server": ts.authorization_server,
        "oauth_client_id": ts.oauth_client_id,
        "revision": ts.revision or 0,
        "description": ts.description,
        "owner": ts.owner,
        "status": ts.status,
        # Blocked, what unblocking gives back.
        "blocked_from": ts.blocked_from,
        "trust_level": ts.trust_level,
        "data_classification": ts.data_classification,
        "labels": ts.labels or {},
        "tools": ts.tools or [],
        "tools_synced_at": ids.isoformat(ts.tools_synced_at),
        "created_by": ts.created_by,
        "created_at": ids.isoformat(ts.created_at),
        "updated_at": ids.isoformat(ts.updated_at),
    }
