"""MCP servers set up on developers' machines, against the approved ones.

``agentgov mcp scan --report`` sends what one person's MCP clients are set up
with on one machine (``agentgov.mcp_scan``); each report replaces that machine
and person's previous one. AgentGov compares every server with the approved
tool servers, by what identifies it (``identity``: its address, or the package or
command that starts it). Reports are sanitised again before they are kept, as the scanner
sanitises them: an address is its scheme, host and port, and a hash of its path.

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

from agentgov import db, ids, ledger, mcp_scan
from agentgov.config import Settings
from agentgov.db.models import BLOCKED, Finding, McpSighting, ToolServer
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


def matcher(tx: db.Transaction, settings: Settings) -> Callable[[str], tuple[str, str | None]]:
    """``identity`` -> (status, the tool server it is). Addresses compare as reported: by
    scheme, host, port and their path's hash (agentgov.mcp_scan.address)."""
    known: dict[str, tuple[str, str]] = {}
    address = mcp_scan.address
    for ts in ToolServer.objects.exclude(status="pending"):
        blocked = ts.status == BLOCKED
        ok = BLOCKED_STATUS if blocked else APPROVED
        if ts.gateway:
            known[f"url:{address(mcp_registry.gateway_url(ts, settings))}"] = (ok, ts.name)
            if ts.url:
                known.setdefault(
                    f"url:{address(ts.url)}", (BLOCKED_STATUS if blocked else BYPASS, ts.name)
                )
        elif ts.url:
            known[f"url:{address(ts.url)}"] = (ok, ts.name)
        for package in ts.packages or []:
            known[f"{package['registry_type']}:{package['identifier']}"] = (ok, ts.name)
            if package.get("command"):
                # The command line developers run, recognised as the scanner recognises it.
                command = mcp_scan.clean_args(package["command"])
                known[mcp_scan.identity_of(None, command)] = (ok, ts.name)

    def match(identity: str) -> tuple[str, str | None]:
        status, server = known.get(mcp_scan.clean_identity(identity), (UNAPPROVED, None))
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


def _sanitised(url: str | None, command: list[str], identity: str) -> tuple[Any, ...]:
    """A server's address, command line and identity, as the scanner reports them now
    (agentgov.mcp_scan): what an older scanner, or anything else, sent holds no more.
    Sanitising them again changes nothing."""
    url = mcp_scan.address(url) if url else None
    if not url and not command and identity.startswith("command:"):
        # Only the identity names the command line: cleaned as one, once.
        command = mcp_scan.command_line(identity.removeprefix("command:"))
    command = mcp_scan.clean_args(command)
    return url, command, mcp_scan.identity_of(url, command) or mcp_scan.clean_identity(identity)


def report(
    tx: db.Transaction,
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
        for s in McpSighting.objects.filter(machine=machine, os_user=user)
    }
    now = ids.utcnow()
    seen = set()
    for i, item in enumerate(servers):
        if not isinstance(item, dict):
            raise ValidationError(f"servers[{i}] must be an object")
        url, command, identity = _sanitised(
            _text(item.get("url"), f"servers[{i}].url", 2000, required=False) or None,
            _strings(item.get("command"), f"servers[{i}].command"),
            _text(item.get("identity"), f"servers[{i}].identity", 400),
        )
        fields = {
            "name": _text(item.get("name"), f"servers[{i}].name", 200),
            "client": _text(item.get("client"), f"servers[{i}].client", 64),
            "scope": _text(item.get("scope") or "user", f"servers[{i}].scope", 16),
            "identity": identity[:400],
            "transport": _text(item.get("transport") or "stdio", f"servers[{i}].transport", 16),
            "url": url,
            "command": command,
            # By name only.
            "env": [v.split("=", 1)[0] for v in _strings(item.get("env"), f"servers[{i}].env")],
            "headers": [
                v.split(":", 1)[0] for v in _strings(item.get("headers"), f"servers[{i}].headers")
            ],
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
        for name, value in fields.items():
            setattr(row, name, value)
        row.last_seen_at = now
        row.reported_by = actor
        row.save(force_insert=row._state.adding)
    dropped = set()
    for key, row in existing.items():
        if key not in seen:
            dropped.add(row.identity)
            row.delete()
    match = matcher(tx, settings)
    statuses = [match(identity)[0] for _, _, _, identity in seen]
    counts = {s: statuses.count(s) for s in (APPROVED, BYPASS, BLOCKED_STATUS, UNAPPROVED)}
    ledger.append(
        tx,
        type="mcp.servers_reported",
        actor=actor,
        resource=f"machine/{machine}",
        severity="warning" if len(seen) - counts[APPROVED] else "info",
        details={"user": user, "servers": len(seen), **counts},
    )
    refresh(tx, settings, {identity for *_, identity in seen} | dropped)
    return {"servers": len(seen), **counts}


def view(
    tx: db.Transaction, settings: Settings, identities: set[str] | None = None
) -> list[dict[str, Any]]:
    """Every server reported (or those of ``identities``), with the machines and people
    that have it and its status."""
    match = matcher(tx, settings)
    groups: dict[str, dict[str, Any]] = {}
    sightings = McpSighting.objects.order_by("-last_seen_at")
    if identities is not None:
        sightings = sightings.filter(identity__in=identities or {""})
    for s in sightings:
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


def refresh(tx: db.Transaction, settings: Settings, identities: set[str] | None = None) -> int:
    """Raise a finding for each reported server that isn't approved, and resolve the rest;
    returns how many resolved. After a report, only for the servers it named or dropped
    (``identities``): the runtime refreshes everything when tool servers change, and hourly."""
    if identities is None:
        cutoff = ids.utcnow() - timedelta(days=KEEP_DAYS)
        McpSighting.objects.filter(last_seen_at__lt=cutoff).delete()
        # Servers reported before addresses were reported by host keep no more either.
        for row in McpSighting.objects.all():
            url, command, identity = _sanitised(row.url, list(row.command or []), row.identity)
            if (url, command, identity[:400]) != (row.url, row.command, row.identity):
                row.url, row.command, row.identity = url, command, identity[:400]
                row.save()
    present: set[str] = set()
    for g in view(tx, settings, identities):
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
            tx,
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
        open_ = Finding.objects.filter(status="open", type__in=types)
        present |= {key for key in open_.values_list("key", flat=True) if key not in scoped}
    return findings.resolve_absent(tx, types=types, present_keys=present, actor=ACTOR)
