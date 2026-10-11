"""MCP servers set up on developers' machines, against the approved ones.

``agentgov mcp scan --report`` sends what one person's MCP clients are set up
with on one machine (``agentgov.mcp_scan``); each report replaces that machine
and person's previous one. AgentGov compares every server with the approved
tool servers, by what identifies it (``identity``: its URL, or the package or
command that starts it):

* approved: a tool server's gateway address, a developer server's own address,
  or a package an approved server lists;
* bypass: the address of a server agents reach through the gateway, used
  directly, past the gateway's controls;
* blocked: a blocked tool server;
* unapproved: anything else (shadow MCP).

Each server that isn't approved raises a finding, which resolves itself once
the server is approved or no machine reports it any more.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger, mcp_scan
from agentgov.config import Settings
from agentgov.models import BLOCKED, Finding, McpSighting, ToolServer
from agentgov.registry import findings, mcp_registry
from agentgov.registry.errors import ValidationError

APPROVED, BYPASS, BLOCKED_STATUS, UNAPPROVED = "approved", "bypass", "blocked", "unapproved"
FINDINGS = {
    UNAPPROVED: ("mcp.unapproved_server", "medium"),
    BYPASS: ("mcp.gateway_bypass", "high"),
    BLOCKED_STATUS: ("mcp.blocked_server", "high"),
}
MAX_SERVERS = 500
KEEP_DAYS = 90  # servers no machine has reported for this long are forgotten
ACTOR = "system:mcp-discovery"


def normal_url(url: str) -> str:
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme.lower(), host, parts.path.rstrip("/"), "", ""))


def matcher(session: Session, settings: Settings) -> Callable[[str], tuple[str, str | None]]:
    """``identity`` -> (status, the tool server it is)."""
    known: dict[str, tuple[str, str]] = {}
    for ts in session.scalars(select(ToolServer).where(ToolServer.status != "pending")):
        blocked = ts.status == BLOCKED
        ok = BLOCKED_STATUS if blocked else APPROVED
        if ts.gateway:
            known[f"url:{normal_url(mcp_registry.gateway_url(ts, settings))}"] = (ok, ts.name)
            if ts.url:
                known.setdefault(
                    f"url:{normal_url(ts.url)}", (BLOCKED_STATUS if blocked else BYPASS, ts.name)
                )
        elif ts.url:
            known[f"url:{normal_url(ts.url)}"] = (ok, ts.name)
        for package in ts.packages or []:
            known[f"{package['registry_type']}:{package['identifier']}"] = (ok, ts.name)
            if package.get("command"):
                # The command line developers run, recognised as the scanner recognises it.
                known[mcp_scan.identity_of(None, package["command"])] = (ok, ts.name)

    def match(identity: str) -> tuple[str, str | None]:
        if identity.startswith("url:"):
            identity = "url:" + normal_url(identity[4:])
        status, server = known.get(identity, (UNAPPROVED, None))
        return status, server

    return match


def _text(value: Any, field: str, limit: int, *, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise ValidationError(f"{field} must be text")
    return value.strip()[:limit]


def _strings(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValidationError(f"{field} must be a list of text")
    return [v[:500] for v in value[:100]]


def report(
    session: Session,
    settings: Settings,
    *,
    machine: Any,
    user: Any,
    servers: Any,
    actor: str,
) -> dict[str, int]:
    """Store one machine and person's MCP servers, replacing their previous report."""
    machine = _text(machine, "machine", 200)
    user = _text(user, "user", 200, required=False)
    if not isinstance(servers, list) or len(servers) > MAX_SERVERS:
        raise ValidationError(f"servers must be a list of at most {MAX_SERVERS}")
    existing = {
        (s.client, s.scope, s.name, s.identity): s
        for s in session.scalars(
            select(McpSighting).where(McpSighting.machine == machine, McpSighting.os_user == user)
        )
    }
    now = ids.utcnow()
    seen = set()
    for i, item in enumerate(servers):
        if not isinstance(item, dict):
            raise ValidationError(f"servers[{i}] must be an object")
        fields = {
            "name": _text(item.get("name"), f"servers[{i}].name", 200),
            "client": _text(item.get("client"), f"servers[{i}].client", 64),
            "scope": _text(item.get("scope") or "user", f"servers[{i}].scope", 16),
            "identity": _text(item.get("identity"), f"servers[{i}].identity", 400),
            "transport": _text(item.get("transport") or "stdio", f"servers[{i}].transport", 16),
            "url": _text(item.get("url"), f"servers[{i}].url", 2000, required=False) or None,
            "command": _strings(item.get("command"), f"servers[{i}].command"),
            "env": _strings(item.get("env"), f"servers[{i}].env"),
            "headers": _strings(item.get("headers"), f"servers[{i}].headers"),
        }
        key = (fields["client"], fields["scope"], fields["name"], fields["identity"])
        if key in seen:
            continue
        seen.add(key)
        row = existing.get(key)
        if row is None:
            row = McpSighting(
                id=ids.new_id(ids.SIGHTING), machine=machine, os_user=user, first_seen_at=now
            )
            session.add(row)
        for name, value in fields.items():
            setattr(row, name, value)
        row.last_seen_at = now
        row.reported_by = actor
    dropped = set()
    for key, row in existing.items():
        if key not in seen:
            dropped.add(row.identity)
            session.delete(row)
    session.flush()
    match = matcher(session, settings)
    statuses = [match(identity)[0] for _, _, _, identity in seen]
    counts = {s: statuses.count(s) for s in (APPROVED, BYPASS, BLOCKED_STATUS, UNAPPROVED)}
    ledger.append(
        session,
        type="mcp.servers_reported",
        actor=actor,
        resource=f"machine/{machine}",
        severity="warning" if len(seen) - counts[APPROVED] else "info",
        details={"user": user, "servers": len(seen), **counts},
    )
    refresh(session, settings, {identity for *_, identity in seen} | dropped)
    return {"servers": len(seen), **counts}


def view(
    session: Session, settings: Settings, identities: set[str] | None = None
) -> list[dict[str, Any]]:
    """Every server reported (or those of ``identities``), with the machines and people
    that have it and its status."""
    match = matcher(session, settings)
    groups: dict[str, dict[str, Any]] = {}
    stmt = select(McpSighting).order_by(McpSighting.last_seen_at.desc())
    if identities is not None:
        stmt = stmt.where(McpSighting.identity.in_(identities or {""}))
    for s in session.scalars(stmt):
        g = groups.setdefault(
            s.identity,
            {
                "identity": s.identity, "transport": s.transport, "url": s.url,
                "command": s.command or [], "names": set(), "clients": set(),
                "machines": set(), "users": set(), "first_seen_at": s.first_seen_at,
                "last_seen_at": s.last_seen_at,
            },
        )  # fmt: skip
        g["names"].add(s.name)
        g["clients"].add(s.client)
        g["machines"].add(s.machine)
        if s.os_user:
            g["users"].add(f"{s.os_user}@{s.machine}")
        g["first_seen_at"] = min(g["first_seen_at"], s.first_seen_at)
        g["last_seen_at"] = max(g["last_seen_at"], s.last_seen_at)
    out = []
    order = {BLOCKED_STATUS: 0, BYPASS: 1, UNAPPROVED: 2, APPROVED: 3}
    for g in groups.values():
        status, server = match(g["identity"])
        out.append(
            {
                **g,
                "names": sorted(g["names"]),
                "clients": sorted(g["clients"]),
                "machines": len(g["machines"]),
                "users": len(g["users"]),
                "first_seen_at": ids.isoformat(g["first_seen_at"]),
                "last_seen_at": ids.isoformat(g["last_seen_at"]),
                "status": status,
                "server": server,
            }
        )
    return sorted(out, key=lambda g: (order[g["status"]], -g["machines"], g["identity"]))


def _what(group: dict[str, Any]) -> str:
    return group["url"] or " ".join(group["command"]) or group["identity"]


def refresh(session: Session, settings: Settings, identities: set[str] | None = None) -> int:
    """Raise a finding for each reported server that isn't approved, and resolve the rest;
    returns how many resolved. After a report, only for the servers it named or dropped
    (``identities``): the runtime refreshes everything when tool servers change, and hourly."""
    if identities is None:
        cutoff = ids.utcnow() - timedelta(days=KEEP_DAYS)
        stale = select(McpSighting).where(McpSighting.last_seen_at < cutoff)
        for old in session.scalars(stale):
            session.delete(old)
        session.flush()
    present: set[str] = set()
    for g in view(session, settings, identities):
        if g["status"] == APPROVED:
            continue
        type_, severity = FINDINGS[g["status"]]
        where = f"{g['machines']} machine{'s' if g['machines'] != 1 else ''}"
        names = ", ".join(g["names"])
        if g["status"] == BYPASS:
            title = f"Developers reach {g['server']} directly, past the gateway"
            description = (
                f"{names} ({_what(g)}) is set up on {where} with the tool server's own address. "
                "Calls there skip the gateway: no policy, inspection or ledger."
            )
            remediation = (
                f"Have developers use {g['server']} through the gateway, and keep the "
                "server's own address off their network."
            )
        elif g["status"] == BLOCKED_STATUS:
            title = f"Developers use the blocked tool server {g['server']}"
            description = (
                f"{names} ({_what(g)}) is set up on {where}, though {g['server']} is blocked."
            )
            remediation = (
                "Have developers remove it. With Copilot's 'Registry only' mode or the "
                "managed-settings allowlist, it can't run."
            )
        else:
            title = f"Developers use an MCP server that isn't approved: {names}"
            description = (
                f"{_what(g)} is set up in {', '.join(g['clients'])} on {where}. "
                "It isn't an approved tool server."
            )
            remediation = (
                "Register it as a tool server for review, or have developers remove it. "
                "With Copilot's 'Registry only' mode or the managed-settings allowlist, only "
                "approved servers run."
            )
        findings.raise_finding(
            session,
            type=type_,
            severity=severity,
            subject=g["identity"][:200],
            category=findings.POSTURE,
            title=title,
            description=description,
            remediation=remediation,
            details={
                "identity": g["identity"],
                "machines": g["machines"],
                "users": g["users"],
                "clients": g["clients"],
            },
        )
        present.add(f"{type_}:{g['identity'][:200]}")
    types = {t for t, _ in FINDINGS.values()}
    if identities is not None:
        # Findings about other servers stand as they are.
        scoped = {f"{t}:{i[:200]}" for t in types for i in identities}
        present |= {
            key
            for key in session.scalars(
                select(Finding.key).where(Finding.status == "open", Finding.type.in_(types))
            )
            if key not in scoped
        }
    return findings.resolve_absent(session, types=types, present_keys=present, actor=ACTOR)
