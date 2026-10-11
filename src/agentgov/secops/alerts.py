"""Alerts for the security team's chats, from ledger entries: findings from a severity up,
approval requests, and kill switches (agents, tool servers, model providers and identity
issuers blocked; agents deleted)."""

from __future__ import annotations

from typing import Any

from agentgov.models import LedgerEntry
from agentgov.registry.destinations import BLOCKS, SEVERITIES
from agentgov.secops.formats import Alert

_BLOCKED = {
    "agent.block": ("Agent", "blocked"),
    "agent.delete": ("Agent", "deleted"),
    "toolserver.block": ("Tool server", "blocked"),
    "model_provider.block": ("Model provider", "blocked"),
    "identity_issuer.block": ("Identity issuer", "blocked"),
}


def _by(actor: str | None) -> str:
    kind, _, name = (actor or "").partition(":")
    if kind == "system":
        return "AgentGov, automatically"
    return name or actor or "someone"


def _name(entry: LedgerEntry) -> str:
    if entry.agent_name:
        return entry.agent_name
    resource = entry.resource or ""
    return resource.split("/", 1)[1] if "/" in resource else resource or "unknown"


def _facts(*pairs: tuple[str, Any]) -> list[tuple[str, str]]:
    return [(label, str(value)) for label, value in pairs if value]


def alert(
    entry: LedgerEntry, *, events: list[str], min_severity: str, public_url: str
) -> Alert | None:
    """The alert a chat gets for this entry, or None. ``min_severity`` applies to findings:
    approval requests and kill switches always go to the chats that take them."""
    details = entry.details or {}
    ui = f"{public_url.rstrip('/')}/ui/#"
    if entry.type in ("finding.raised", "finding.reopened") and "findings" in events:
        severity = str(details.get("severity") or "info")
        if severity not in SEVERITIES or SEVERITIES.index(severity) < SEVERITIES.index(
            min_severity
        ):
            return None
        reopened = entry.type == "finding.reopened"
        subject = entry.resource if entry.resource != entry.agent_id else None
        return Alert(
            title=f"{severity.capitalize()} finding{' (again)' if reopened else ''}: "
            f"{entry.reason or details.get('type') or 'finding'}",
            text=str(details.get("description") or entry.reason or ""),
            severity=severity,
            facts=_facts(
                ("Agent", entry.agent_name),
                ("Finding", details.get("type")),
                ("Subject", subject),
                ("What to do", details.get("remediation")),
            ),
            # The finding's own page: who it went to, and what happened to it.
            link=f"{ui}/findings/{details['finding_id']}"
            if details.get("finding_id")
            else f"{ui}/findings",
            link_label="Open the finding",
        )
    if entry.type == "approval.requested" and "approvals" in events:
        person = entry.on_behalf_of
        decides = (
            f"{person} decides it"
            if details.get("deciders") == "person" and person
            else "an approver decides it"
        )
        return Alert(
            title=f"Approval needed: {_name(entry)} wants to call {entry.resource}",
            text=f"The call waits until {decides}.",
            severity="medium",
            facts=_facts(
                ("Agent", entry.agent_name),
                ("Call", entry.resource),
                ("For", person),
                ("Why", entry.reason),
            ),
            link=f"{ui}/approvals",
            link_label="Decide in AgentGov",
        )
    if entry.type in BLOCKS and "blocks" in events:
        if entry.type == "platform.agent_blocked":
            what, done = "Agent", f"blocked in {details.get('platform') or 'its platform'}"
        else:
            what, done = _BLOCKED[entry.type]
        link = f"{ui}/agents/{entry.agent_id}" if entry.agent_id else f"{ui}/overview"
        return Alert(
            title=f"{what} {_name(entry)} {done}",
            text=f"By {_by(entry.actor)}" + (f": {entry.reason}" if entry.reason else "."),
            severity="high",
            facts=_facts(("By", entry.actor), ("Why", entry.reason)),
            link=link,
        )
    return None


def summary(count: int, public_url: str) -> Alert:
    """In place of alerts beyond what a chat takes at once."""
    return Alert(
        title=f"{count} more alerts",
        text="More happened than this channel is sent at once: see AgentGov for the rest.",
        severity="high",
        link=f"{public_url.rstrip('/')}/ui/#/findings",
    )
